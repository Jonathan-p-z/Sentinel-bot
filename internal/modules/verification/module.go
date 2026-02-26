package verification

import "context"

type Module struct{}

func New() *Module {
	return &Module{}
}

func (m *Module) HandleVerify(ctx context.Context) {
	_ = ctx
}
