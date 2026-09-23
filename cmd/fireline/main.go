// Command fireline is Fireline's single application binary: API, import
// jobs, migrations, policy evaluation, and CLI all in one (D-12). This pass
// only wires up migrations and a one-shot import round trip; the rest
// arrives with later phases.
package main

import (
	"fmt"
	"os"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "fireline:", err)
		os.Exit(1)
	}
}
