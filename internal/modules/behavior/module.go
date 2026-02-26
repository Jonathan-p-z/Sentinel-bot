package behavior

import "context"

type Module struct{}

func New() *Module {
	return &Module{}
}

func (m *Module) HandleMessage(ctx context.Context) {
	_ = ctx
}
