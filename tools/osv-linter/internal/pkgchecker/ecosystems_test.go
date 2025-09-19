package pkgchecker

import "testing"

func Test_versionsExistInCran(t *testing.T) {
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
				pkg:      "gdata",
				versions: []string{"2.7.1", "2.12.0.2", "2.18.0.1", "2.19.0"},
			},
			wantErr: false,
		},
		{
			name: "multiple_versions_with_one_that_does_not_exist",
			args: args{
				pkg:      "gdata",
				versions: []string{"2.4.1", "2.9.1", "2.12.0"},
			},
			wantErr: true,
		},
		{
			name: "an_invalid_version",
			args: args{
				pkg:      "gdata",
				versions: []string{"!"},
			},
			wantErr: true,
		},
		{
			name: "an_invalid_package",
			args: args{
				pkg:      "!",
				versions: []string{"1.0.0"},
			},
			wantErr: true,
		},
		{
			name: "a_package_that_does_not_exit",
			args: args{
				pkg:      "not-a-real-package-hopefully",
				versions: []string{"1.0.0"},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if err := versionsExistInCran(tt.args.pkg, tt.args.versions); (err != nil) != tt.wantErr {
				t.Errorf("versionsExistInCran() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_versionsExistInCrates(t *testing.T) {
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
				pkg:      "defmt",
				versions: []string{"0.0.0", "0.3.0", "0.3.100-rc.1", "1.0.0-rc.1", "1.0.1"},
			},
			wantErr: false,
		},
		{
			name: "multiple_versions_with_one_that_does_not_exist",
			args: args{
				pkg:      "defmt",
				versions: []string{"1.1", "0.3.6-beta", "1.1.2"},
			},
			wantErr: true,
		},
		{
			name: "an_invalid_version",
			args: args{
				pkg:      "defmt",
				versions: []string{"!"},
			},
			wantErr: true,
		},
		{
			name: "an_invalid_package",
			args: args{
				pkg:      "!",
				versions: []string{"1.0.0"},
			},
			wantErr: true,
		},
		{
			name: "a_package_that_does_not_exit",
			args: args{
				pkg:      "not-a-real-package-hopefully",
				versions: []string{"1.0.0"},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if err := versionsExistInCrates(tt.args.pkg, tt.args.versions); (err != nil) != tt.wantErr {
				t.Errorf("versionsExistInCrates() error = %v, wantErr %v", err, tt.wantErr)
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

func Test_versionsExistInHackage(t *testing.T) {
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
				pkg:      "aeson",
				versions: []string{"0.1.0.0", "1.4.7.1", "2.2.2.0"},
			},
			wantErr: false,
		},
		{
			name: "multiple_versions_with_one_that_does_not_exist",
			args: args{
				pkg:      "aeson",
				versions: []string{"1.1", "2.0.0-beta1", "3.1.5", "2.2.2.2"},
			},
			wantErr: true,
		},
		{
			name: "an_invalid_version",
			args: args{
				pkg:      "aeson",
				versions: []string{"!"},
			},
			wantErr: true,
		},
		{
			name: "an_invalid_package",
			args: args{
				pkg:      "!",
				versions: []string{"1.0.0"},
			},
			wantErr: true,
		},
		{
			name: "a_package_that_does_not_exit",
			args: args{
				pkg:      "not-a-real-package-hopefully",
				versions: []string{"1.0.0"},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if err := versionsExistInHackage(tt.args.pkg, tt.args.versions); (err != nil) != tt.wantErr {
				t.Errorf("versionsExistInHackage() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_versionsExistInHex(t *testing.T) {
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
				pkg:      "jason",
				versions: []string{"1.0.0-rc.2", "1.0.0", "1.2.2", "1.5.0-alpha.2"},
			},
			wantErr: false,
		},
		{
			name: "multiple_versions_with_one_that_does_not_exist",
			args: args{
				pkg:      "jason",
				versions: []string{"1.0.0-rc.3", "1.3.3", "1.4.4"},
			},
			wantErr: true,
		},
		{
			name: "an_invalid_version",
			args: args{
				pkg:      "jason",
				versions: []string{"!"},
			},
			wantErr: true,
		},
		{
			name: "an_invalid_package",
			args: args{
				pkg:      "!",
				versions: []string{"1.0.0"},
			},
			wantErr: true,
		},
		{
			name: "a_package_that_does_not_exit",
			args: args{
				pkg:      "not-a-real-package-hopefully",
				versions: []string{"1.0.0"},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if err := versionsExistInHex(tt.args.pkg, tt.args.versions); (err != nil) != tt.wantErr {
				t.Errorf("versionsExistInHex() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_versionsExistInNpm(t *testing.T) {
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
				pkg:      "semver",
				versions: []string{"1.0.1", "2.0.0-beta", "5.7.1"},
			},
			wantErr: false,
		},
		{
			name: "multiple_versions_with_one_that_does_not_exist",
			args: args{
				pkg:      "semver",
				versions: []string{"1.1", "2.0.0-beta1", "3.1.5", "5.1rc1"},
			},
			wantErr: true,
		},
		{
			name: "an_invalid_version",
			args: args{
				pkg:      "semver",
				versions: []string{"!"},
			},
			wantErr: true,
		},
		{
			name: "an_invalid_package",
			args: args{
				pkg:      "!",
				versions: []string{"1.0.0"},
			},
			wantErr: true,
		},
		{
			name: "a_package_that_does_not_exit",
			args: args{
				pkg:      "not-a-real-package-hopefully",
				versions: []string{"1.0.0"},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if err := versionsExistInNpm(tt.args.pkg, tt.args.versions); (err != nil) != tt.wantErr {
				t.Errorf("versionsExistInNpm() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_versionsExistInNuGet(t *testing.T) {
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
				pkg:      "CouchbaseNetClient",
				versions: []string{"0.9.0", "1.2.0-beta-2", "3.6.5-buildbot-r8718", "3.6.5"},
			},
			wantErr: false,
		},
		{
			name: "multiple_versions_with_one_that_does_not_exist",
			args: args{
				pkg:      "CouchbaseNetClient",
				versions: []string{"0.9.1", "2.0.0-beta", "2.2.0-dp2", "2.7.27"},
			},
			wantErr: true,
		},
		{
			name: "an_invalid_version",
			args: args{
				pkg:      "CouchbaseNetClient",
				versions: []string{"!"},
			},
			wantErr: true,
		},
		{
			name: "an_invalid_package",
			args: args{
				pkg:      "!",
				versions: []string{"1.0.0"},
			},
			wantErr: true,
		},
		{
			name: "a_package_that_does_not_exit",
			args: args{
				pkg:      "not-a-real-package-hopefully",
				versions: []string{"1.0.0"},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if err := versionsExistInNuGet(tt.args.pkg, tt.args.versions); (err != nil) != tt.wantErr {
				t.Errorf("versionsExistInNuGet() error = %v, wantErr %v", err, tt.wantErr)
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

func Test_versionsExistInPub(t *testing.T) {
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
				pkg:      "agent_dart",
				versions: []string{"0.0.1", "0.1.14+1", "0.1.24", "1.0.0-dev.11"},
			},
			wantErr: false,
		},
		{
			name: "multiple_versions_with_one_that_does_not_exist",
			args: args{
				pkg:      "agent_dart",
				versions: []string{"0.1.1", "0.1.15+4", "1.0.0-dev.17"},
			},
			wantErr: true,
		},
		{
			name: "an_invalid_version",
			args: args{
				pkg:      "agent_dart",
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

			if err := versionsExistInPub(tt.args.pkg, tt.args.versions); (err != nil) != tt.wantErr {
				t.Errorf("versionsExistInPub() error = %v, wantErr %v", err, tt.wantErr)
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
