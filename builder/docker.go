// Copyright 2020 Limejuice-cc Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package builder

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/limejuice-cc/limepacker/manifest"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/rs/zerolog/log"
)

type dockerBuildFile struct {
	name string
	body []byte
}

type dockerBuilder struct {
	baseBuilder

	dockerFile   string
	dockerIgnore string
	extraFiles   []*dockerBuildFile

	tags      []string
	buildArgs map[string]*string

	outputDirectory string
	output          []byte
	imageID         string
}

type dockerResponseLine struct {
	value map[string]interface{}
}

func (l *dockerResponseLine) IsStream() bool {
	_, ok := l.value["stream"]
	return ok
}

func (l *dockerResponseLine) Stream() string {
	v, ok := l.value["stream"]
	if !ok {
		return ""
	}
	return strings.TrimSpace(v.(string))
}

func (l *dockerResponseLine) IsAux() bool {
	_, ok := l.value["aux"]
	return ok
}

func (l *dockerResponseLine) Aux() map[string]interface{} {
	v, ok := l.value["aux"]
	if !ok {
		return nil
	}
	return v.(map[string]interface{})
}

func (l *dockerResponseLine) String() string {
	var sb strings.Builder
	for k, v := range l.value {
		fmt.Fprintf(&sb, "%s: %v", k, v)
	}
	return sb.String()
}

type dockerResponse struct {
	lines []*dockerResponseLine
}

type dockerImageID string

func (i dockerImageID) Hash() string {
	parts := strings.Split(string(i), ":")
	if len(parts) != 2 {
		log.Panic().Msgf("cannot parse %s", string(i))
		return ""
	}
	return parts[1]
}

func (r *dockerResponse) ImageID() dockerImageID {
	for i := range r.lines {
		v := r.lines[len(r.lines)-1-i]
		if !v.IsAux() {
			continue
		}
		a := v.Aux()
		if id, ok := a["ID"]; !ok {
			continue
		} else {
			return dockerImageID(id.(string))
		}
	}
	return ""
}

func (r *dockerResponse) String() string {
	lines := make([]string, len(r.lines))
	for i, l := range r.lines {
		lines[i] = strings.TrimSpace(l.String())
	}
	return strings.Join(lines, "\n")
}

func parseDockerResponse(in string) (*dockerResponse, error) {
	out := &dockerResponse{lines: []*dockerResponseLine{}}
	scanner := bufio.NewScanner(strings.NewReader(in))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		v := map[string]interface{}{}
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			return nil, err
		}
		resp := &dockerResponseLine{value: v}
		if resp.IsStream() {
			if len(strings.TrimSpace(resp.Stream())) == 0 {
				continue
			}
		}
		out.lines = append(out.lines, resp)
	}
	return out, nil
}

func (b *dockerBuilder) createContext() (io.Reader, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	if err := writeDockerFile(tw, "Dockerfile", []byte(b.dockerFile)); err != nil {
		return nil, err
	}

	if b.dockerIgnore != "" {
		if err := writeDockerFile(tw, ".dockerignore", []byte(b.dockerIgnore)); err != nil {
			return nil, err
		}
	}

	for _, f := range b.extraFiles {
		if err := writeDockerFile(tw, f.name, f.body); err != nil {
			return nil, err
		}
	}

	if err := tw.Close(); err != nil {
		return nil, err
	}
	return bytes.NewReader(buf.Bytes()), nil
}

func writeDockerFile(tw *tar.Writer, name string, body []byte) error {
	hdr := &tar.Header{Name: name, Size: int64(len(body))}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	if _, err := tw.Write(body); err != nil {
		return err
	}
	return nil
}

func (b *dockerBuilder) createBuildOptions() (*types.ImageBuildOptions, error) {
	ctx, err := b.createContext()
	if err != nil {
		return nil, err
	}
	return &types.ImageBuildOptions{
		Context:    ctx,
		Dockerfile: "Dockerfile",
		Tags:       b.tags,
		BuildArgs:  b.buildArgs,

		Remove: true,
	}, nil
}

func (b *dockerBuilder) build() (*dockerResponse, error) {
	buildOptions, err := b.createBuildOptions()
	if err != nil {
		return nil, err
	}
	cli, err := client.NewClientWithOpts()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	buildResponse, err := cli.ImageBuild(ctx, buildOptions.Context, *buildOptions)
	if err != nil {
		return nil, err
	}
	defer buildResponse.Body.Close()
	var sb strings.Builder
	if _, err := io.Copy(&sb, buildResponse.Body); err != nil {
		return nil, err
	}
	resp, err := parseDockerResponse(sb.String())
	b.imageID = resp.ImageID().Hash()
	return resp, err
}

func (b *dockerBuilder) platform() *specs.Platform {
	return &specs.Platform{
		Architecture: b.Architecture(),
		OS:           b.OS(),
		Variant:      b.Variant(),
	}
}

func (b *dockerBuilder) exec() error {
	cli, err := client.NewClientWithOpts()
	if err != nil {
		return err
	}

	ctx := context.Background()
	config := &container.Config{
		Image: b.imageID,
	}
	hostConfig := &container.HostConfig{}
	networkingConfig := &network.NetworkingConfig{}
	platform := b.platform()
	containerName := ""

	createResponse, err := cli.ContainerCreate(ctx, config, hostConfig, networkingConfig, platform, containerName)
	if err != nil {
		return err
	}

	options := types.ContainerStartOptions{}

	if err := cli.ContainerStart(ctx, createResponse.ID, options); err != nil {
		return err
	}

	r, _, err := cli.CopyFromContainer(ctx, createResponse.ID, b.outputDirectory)
	if err != nil {
		return err
	}
	defer r.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		return err
	}

	b.output = buf.Bytes()

	if err := cli.ContainerStop(ctx, createResponse.ID, nil); err != nil {
		return err
	}

	removeOptions := types.ContainerRemoveOptions{Force: true, RemoveVolumes: true}
	if err := cli.ContainerRemove(ctx, createResponse.ID, removeOptions); err != nil {
		return err
	}

	return nil
}

func (b *dockerBuilder) remove() error {
	cli, err := client.NewClientWithOpts()
	if err != nil {
		return err
	}
	ctx := context.Background()
	options := types.ImageRemoveOptions{
		Force:         true,
		PruneChildren: true,
	}
	if _, err := cli.ImageRemove(ctx, b.imageID, options); err != nil {
		return err
	}
	return nil
}

func (b *dockerBuilder) extractResults() (Results, error) {
	r := bytes.NewReader(b.output)
	tr := tar.NewReader(r)

	results := newResults()

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			return nil, err
		}
		if hdr.FileInfo().IsDir() {
			continue
		}
		f, err := newFile(tr, hdr.Name, hdr.Uname, hdr.Gname, hdr.FileInfo().Mode(), manifest.NotSpecified)
		if err != nil {
			return nil, err
		}
		results.files = append(results.files, f)
	}

	return results, nil
}

func (b *dockerBuilder) Run() (Results, error) {
	log.Info().Msg("Starting docker build")
	log.Info().Msg("Building docker image")

	if resp, err := b.build(); err == nil {
		log.Info().Msg("Docker image built")
		log.Info().Msg(resp.String())
	} else {
		log.Error().Msgf("Error building docker image")
		return nil, err
	}
	log.Info().Msg("Running docker container")
	if err := b.exec(); err != nil {
		log.Error().Msg("Error running docker container")
		return nil, err
	}
	log.Info().Msg("Cleaning up")
	if err := b.remove(); err != nil {
		log.Error().Msg("Error removing docker image")
		return nil, err
	}
	log.Info().Msg("Docker build ran successfully")
	return b.extractResults()
}

// DockerBuildOption specifies options for a Docker Build
type DockerBuildOption interface {
	Apply(build interface{}) error
}

type dockerIgnoreOption struct {
	dockerIgnore string
}

func (o *dockerIgnoreOption) Apply(build interface{}) error {
	b, ok := build.(*dockerBuilder)
	if !ok {
		return errors.New("unexpected error")
	}
	b.dockerIgnore = o.dockerIgnore
	return nil
}

//WithDockerIgnore creates an optional .dockerignore file
func WithDockerIgnore(dockerIgnore string) DockerBuildOption {
	return &dockerIgnoreOption{dockerIgnore: dockerIgnore}
}

type dockerExtraFileOption struct {
	name string
	body []byte
}

func (o *dockerExtraFileOption) Apply(build interface{}) error {
	b, ok := build.(*dockerBuilder)
	if !ok {
		return errors.New("unexpected error")
	}
	b.extraFiles = append(b.extraFiles, &dockerBuildFile{name: o.name, body: o.body})
	return nil
}

// WithFile specifies optional files
func WithFile(name string, reader io.Reader) DockerBuildOption {
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, reader); err != nil {
		log.Panic().Msg("error cannot read file")
		return nil
	}
	return &dockerExtraFileOption{name: name, body: buf.Bytes()}
}

// NewDockerBuild creates a new Docker Build
func NewDockerBuild(dockerFile, outputDirectory string, options ...DockerBuildOption) (Build, error) {
	out := &dockerBuilder{
		dockerFile:      dockerFile,
		dockerIgnore:    "",
		extraFiles:      []*dockerBuildFile{},
		tags:            []string{},
		buildArgs:       map[string]*string{},
		outputDirectory: outputDirectory,
	}
	for _, opt := range options {
		if err := opt.Apply(out); err != nil {
			return nil, err
		}
	}
	if out.outputDirectory == "" {
		return nil, fmt.Errorf("must specify an output directory")
	}
	return out, nil
}
