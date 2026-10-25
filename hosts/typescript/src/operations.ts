import { Duplex } from "node:stream";
import { fail, type Context, type Provider, type Types } from "./provider.js";

type AsyncPort = {
  [K in keyof Provider]-?: NonNullable<Provider[K]> extends (
    ...args: never[]
  ) => Promise<unknown>
    ? K
    : never;
}[keyof Provider];
export type Operation = Exclude<AsyncPort, "run">;
type OptionalOperation = {
  [K in Operation]: undefined extends Provider[K] ? K : never;
}[Operation];
type BooleanCapability = {
  [K in keyof Types["Capabilities"]]-?: NonNullable<
    Types["Capabilities"][K]
  > extends boolean
    ? K
    : never;
}[keyof Types["Capabilities"]];
type Port<K extends Operation> = Extract<
  NonNullable<Provider[K]>,
  (...args: never[]) => Promise<unknown>
>;
export type OperationArgs<K extends Operation> =
  Parameters<Port<K>> extends [...infer Args, Context] ? Args : never;
export type OperationResult<K extends Operation> = Awaited<ReturnType<Port<K>>>;

// One declaration covers registration, admission, checked invocation and the
// reference module's optional-operation controls. A new optional port must map here.
const capabilities = {
  exec: "fallback_runner",
  suspend: "suspend_resume",
  resume: "suspend_resume",
  export: "export",
  usage: "usage",
  quota: "quota",
} as const satisfies Record<OptionalOperation, BooleanCapability>;
const optional = Object.keys(capabilities) as OptionalOperation[];
export const optionalControls = optional.filter(
  (key, index) =>
    optional.findIndex((other) => capabilities[other] === capabilities[key]) ===
    index,
);

export function checkDeclaration(provider: Provider): void {
  for (const operation of optional)
    if (
      provider.capabilities[capabilities[operation]] !==
      (typeof provider[operation] === "function")
    )
      fail("refused", "capabilities must match optional operation ports");
}
export function checkSupported(
  declaration: Types["Capabilities"],
  operation: Operation,
): void {
  if (
    operation in capabilities &&
    !declaration[capabilities[operation as OptionalOperation]]
  )
    fail("refused", "unsupported operation");
}
export function disableOperations(
  provider: Provider,
  controls: string[],
): void {
  for (const control of controls) {
    if (!optionalControls.includes(control as OptionalOperation))
      fail("refused", "invalid optional operation");
    const capability = capabilities[control as OptionalOperation];
    provider.capabilities[capability] = false;
    for (const operation of optional)
      if (capabilities[operation] === capability)
        Object.defineProperty(provider, operation, { value: undefined });
  }
}
export async function invoke<K extends Operation>(
  provider: Provider,
  operation: K,
  args: OperationArgs<K>,
  context: Context,
): Promise<OperationResult<K>> {
  const port = provider[operation];
  if (typeof port !== "function") fail("refused", "operation port unavailable");
  const value = (await Reflect.apply(port, provider, [
    ...args,
    context,
  ])) as OperationResult<K>;
  // The call gate can stop waiting before an uncooperative provider completes.
  if (context.signal.aborted && value instanceof Duplex) value.destroy();
  return value;
}
