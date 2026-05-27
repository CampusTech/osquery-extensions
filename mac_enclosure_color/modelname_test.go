package main

import "testing"

func TestParseModelName(t *testing.T) {
	cases := []struct {
		name string
		json string
		want string
	}{
		{
			name: "MacBook Pro",
			json: `{"SPHardwareDataType":[{"machine_name":"MacBook Pro","machine_model":"Mac16,5"}]}`,
			want: "MacBook Pro",
		},
		{
			name: "Mac Studio",
			json: `{"SPHardwareDataType":[{"machine_name":"Mac Studio"}]}`,
			want: "Mac Studio",
		},
		{
			name: "empty array",
			json: `{"SPHardwareDataType":[]}`,
			want: "",
		},
		{
			name: "missing key",
			json: `{}`,
			want: "",
		},
		{
			name: "malformed json",
			json: `not json`,
			want: "",
		},
		{
			name: "empty input",
			json: ``,
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseModelName([]byte(tc.json))
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
