// The Modal module with its vendor stood in, as a module the host loads
// through DRYDOCK_TYPESCRIPT_MODULES, so drydock's conformance suite runs
// against it through drydockd (crates/drydock/tests/typescript.rs). It is the
// built module, so its errors are the classes the host's server knows.
import { modalModule } from "../../dist/modal/index.js";
import { StandIn } from "./modal.ts";

const standIn = new StandIn();
// Registries resolve to a public address; the module checks, Modal pulls.
const module = modalModule(standIn.connect, async () => ["192.0.2.1"]);

export default { ...module, name: "modal-stand-in" };
