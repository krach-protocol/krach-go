module github.com/connctd/krach

go 1.12

require (
	github.com/cevatbarisyilmaz/lossy v0.2.0
	github.com/flynn/noise v0.0.0-20180327030543-2492fe189ae6
	github.com/pkg/errors v0.8.1
	github.com/sirupsen/logrus v1.4.2
	github.com/stretchr/testify v1.3.0
	github.com/ugorji/go v1.1.4
	github.com/xtaci/smux v1.2.2
	golang.org/x/crypto v0.0.0-20191122220453-ac88ee75c92c
	golang.org/x/sys v0.0.0-20191126131656-8a8471f7e56d // indirect
	gopkg.in/yaml.v2 v2.2.7 // indirect
)

replace github.com/flynn/noise => github.com/connctd/noise v0.0.0-20191126144203-70477de8908c
