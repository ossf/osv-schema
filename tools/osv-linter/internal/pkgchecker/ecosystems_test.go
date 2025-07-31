package pkgchecker

import "testing"

func Test_versionsExistInPyPI(t *testing.T) {
	t.Parallel()

	type args struct {
		pkg      string
		versions []string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "multiple_versions_which_all_exist",
			args: args{
				pkg:      "Django",
				versions: []string{"1.1.1", "3.1.5", "5.1rc1"},
			},
			wantErr: false,
		},
		{
			name: "multiple_versions_with_one_that_does_not_exist",
			args: args{
				pkg:      "Django",
				versions: []string{"1.1.1", "2.3rc9", "3.1.5", "5.1rc1"},
			},
			wantErr: true,
		},
		{
			name: "an_invalid_version",
			args: args{
				pkg:      "django",
				versions: []string{"!"},
			},
			wantErr: true,
		},
		{
			name: "an_unnormalized_name",
			args: args{
				pkg:      "Django",
				versions: []string{"1.1.1"},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if err := versionsExistInPyPI(tt.args.pkg, tt.args.versions); (err != nil) != tt.wantErr {
				t.Errorf("versionsExistInPyPI() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_versionsExistInGo(t *testing.T) {
	type args struct {
		pkg      string
		versions []string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "an unreleased package",
			args: args{
				pkg:      "github.com/nanobox-io/golang-nanoauth",
				versions: nil,
			},
			wantErr: false,
		},
		{
			name: "a released package",
			args: args{
				pkg:      "github.com/oauth2-proxy/oauth2-proxy",
				versions: []string{"1.1.1"},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := versionsExistInGo(tt.args.pkg, tt.args.versions); (err != nil) != tt.wantErr {
				t.Errorf("versionsExistInGo() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
