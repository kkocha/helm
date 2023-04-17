/*
Copyright The Helm Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"fmt"
	"io"
	"log"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"helm.sh/helm/v3/cmd/helm/require"
	"helm.sh/helm/v3/pkg/cli/output"
)

var envHelp = `
Env prints out all the environment information in use by Helm.
`

// var outputFormat string
const envOutputFlag string = "output"

func newEnvCmd(out io.Writer) *cobra.Command {
	var envOutFmt envFormat
	cmd := &cobra.Command{
		Use:   "env",
		Short: "helm client environment information",
		Long:  envHelp,
		Args:  require.MaximumNArgs(1),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if len(args) == 0 {
				keys := getSortedEnvVarKeys()
				return keys, cobra.ShellCompDirectiveNoFileComp
			}

			return nil, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			envVars := settings.EnvVars()

			if len(args) == 0 {
				return envOutFmt.WriteEnvs(out, envVars)
			}

			key := args[0]
			return envOutFmt.WriteOneEnv(out, envOutFmt, key, envVars[key])
		},
	}

	// cmd.Flags().StringVarP(&outputFormat, "output", "o", "env", fmt.Sprintf("change the output from `env(key=value)` to the specified format. Allowed values: %s", strings.Join(envFormats(), ", ")))
	cmd.Flags().VarP(newEnvOutputValue(keyValueEnv, &envOutFmt), envOutputFlag, "o", fmt.Sprintf("prints the environment information in the specified format. Allowed values: %s", strings.Join(envFormats(), ", ")))
	err := cmd.RegisterFlagCompletionFunc(envOutputFlag, func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		var formatNames []string
		for format, desc := range envFormatsWithDesc() {
			formatNames = append(formatNames, fmt.Sprintf("%s\t%s", format, desc))
		}

		// Sort the results to get a deterministic order for the tests
		sort.Strings(formatNames)
		return formatNames, cobra.ShellCompDirectiveNoFileComp
	})

	if err != nil {
		log.Fatal(err)
	}

	return cmd
}

type envs map[string]string

type envFormat string
type envOutputValue envFormat

const (
	keyValueEnv envFormat = "env"
	jsonEnv     envFormat = "json"
	yamlEnv     envFormat = "yaml"
)

func envFormats() []string {
	return []string{keyValueEnv.String(), jsonEnv.String(), yamlEnv.String()}
}

func (o envFormat) String() string {
	return string(o)
}

func newEnvOutputValue(defaultValue envFormat, p *envFormat) *envOutputValue {
	*p = defaultValue
	return (*envOutputValue)(p)
}

func (o *envOutputValue) String() string {
	return string(*o)
}

func (o *envOutputValue) Set(s string) error {
	outfmt, err := parseFormat(s)
	if err != nil {
		return err
	}
	*o = envOutputValue(outfmt)
	return nil
}

func (o *envOutputValue) Type() string {
	return "format"
}

func parseFormat(s string) (out envFormat, err error) {
	switch s {
	case keyValueEnv.String():
		out, err = keyValueEnv, nil
	case jsonEnv.String():
		out, err = jsonEnv, nil
	case yamlEnv.String():
		out, err = yamlEnv, nil
	default:
		out, err = "", output.ErrInvalidFormatType
	}
	return
}

func envFormatsWithDesc() map[string]string {
	return map[string]string{
		keyValueEnv.String(): "Output result in key-value format",
		jsonEnv.String():     "Output result in JSON format",
		yamlEnv.String():     "Output result in YAML format",
	}
}

func getSortedEnvVarKeys() []string {
	envVars := settings.EnvVars()

	var keys []string
	for k := range envVars {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	return keys
}

type EnvWriter interface {
	WriteEnvs(out io.Writer, e envs) error
	WriteOneEnv(out io.Writer, key, value string) error
}

func (f envFormat) WriteEnvs(out io.Writer, e envs) error {
	switch f {
	case keyValueEnv:
		return writeKeyValues(out, e)
	case jsonEnv:
		return output.EncodeJSON(out, e)
	case yamlEnv:
		return output.EncodeYAML(out, e)
	default:
		return output.ErrInvalidFormatType
	}
}

func (f envFormat) WriteOneEnv(out io.Writer, format envFormat, key, value string) error {
	switch f {
	case keyValueEnv:
		fmt.Fprintf(out, "%s\n", value)
		return nil
	case jsonEnv:
		return output.EncodeJSON(out, map[string]string{key: value})
	case yamlEnv:
		return output.EncodeYAML(out, map[string]string{key: value})
	default:
		return output.ErrInvalidFormatType
	}
}

func writeKeyValues(out io.Writer, e envs) error {
	keys := getSortedEnvVarKeys()

	// Sort the variables by alphabetical order.
	// This allows for a constant output across calls to 'helm env'.
	for _, k := range keys {
		fmt.Fprintf(out, "%s=\"%s\"\n", k, e[k])
	}
	return nil
}
