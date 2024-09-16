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
