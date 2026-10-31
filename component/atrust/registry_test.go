package atrust

import "testing"

func TestRegisterProviderKeepsReplacement(t *testing.T) {
	first := &Client{options: Options{Name: "atrust"}}
	second := &Client{options: Options{Name: "atrust"}}

	unregisterFirst := RegisterProvider(first)
	unregisterSecond := RegisterProvider(second)
	defer unregisterSecond()

	unregisterFirst()
	if provider, ok := ProviderByName("atrust"); !ok || provider != second {
		t.Fatalf("replacement provider was removed by the old unregister: %v", provider)
	}
}
