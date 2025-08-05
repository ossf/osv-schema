package pkgchecker

import "testing"

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

func Test_versionsExistInPackagist(t *testing.T) {
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
				pkg:      "composer/installers",
				versions: []string{"1.0.7", "2.0.0-alpha1", "2.3.0"},
			},
			wantErr: false,
		},
		{
			name: "multiple_versions_which_all_exist_prefixed_with_v",
			args: args{
				pkg:      "composer/installers",
				versions: []string{"v1.0.7", "v2.0.0-alpha1", "v2.3.0"},
			},
			wantErr: false,
		},
		{
			name: "multiple_versions_with_one_that_does_not_exist",
			args: args{
				pkg:      "composer/installers",
				versions: []string{"1.1.1", "2.3rc9", "3.1.5", "5.1rc1"},
			},
			wantErr: true,
		},
		{
			name: "an_invalid_version",
			args: args{
				pkg:      "composer/installers",
				versions: []string{"!"},
			},
			wantErr: true,
		},
		{
			name: "a_package_that_does_not_exit",
			args: args{
				pkg:      "not-a-real-package",
				versions: []string{"1.0.0"},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if err := versionsExistInPackagist(tt.args.pkg, tt.args.versions); (err != nil) != tt.wantErr {
				t.Errorf("versionsExistInPackagist() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

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
				pkg:      "django",
				versions: []string{"1.1.1", "3.1.5", "5.1rc1"},
			},
			wantErr: false,
		},
		{
			name: "multiple_versions_with_one_that_does_not_exist",
			args: args{
				pkg:      "django",
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
			name: "a_package_that_does_not_exit",
			args: args{
				pkg:      "not-a-real-package",
				versions: []string{},
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

func Test_versionsExistInRubyGems(t *testing.T) {
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
				pkg:      "capistrano",
				versions: []string{"2.5.7", "3.0.0.pre4", "3.11.1"},
			},
			wantErr: false,
		},
		{
			name: "multiple_versions_with_one_that_does_not_exist",
			args: args{
				pkg:      "capistrano",
				versions: []string{"1.1.1", "2.3rc9", "3.1.5", "5.1rc1"},
			},
			wantErr: true,
		},
		{
			name: "an_invalid_version",
			args: args{
				pkg:      "capistrano",
				versions: []string{"!"},
			},
			wantErr: true,
		},
		{
			name: "a_package_that_does_not_exit",
			args: args{
				pkg:      "not-a-real-package",
				versions: []string{"1.0.0"},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if err := versionsExistInRubyGems(tt.args.pkg, tt.args.versions); (err != nil) != tt.wantErr {
				t.Errorf("versionsExistInRubyGems() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
