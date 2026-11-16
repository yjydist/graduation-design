package agent

import "context"

// RequestQuote runs the same wallet tool used by MCP without an LLM driver.
func (w *WalletContext) RequestQuote(ctx context.Context, in RequestQuoteInput) (RequestQuoteOutput, error) {
	_, out, err := w.handleRequestQuote(ctx, nil, in)
	return out, err
}

// CreateOrder runs the same intent, fresh-challenge and holder-proof path used by MCP.
func (w *WalletContext) CreateOrder(ctx context.Context, in CreateOrderInput) (CreateOrderOutput, error) {
	_, out, err := w.handleCreateOrder(ctx, nil, in)
	return out, err
}
