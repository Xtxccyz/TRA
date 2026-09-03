declare module '@deepseek-ai/cordis' {
  export interface Context { tools: { register(value: unknown): unknown } }
}

declare module '@deepseek-ai/dsh-session' {
  export interface Session { append(type: string, data: Record<string, unknown>): unknown }
  export const KNOWN_SESSION_EVENT_TYPES: ReadonlySet<string>
}

declare module '@deepseek-ai/dsh-client-runtime/client' {
  export interface ClientSlots {
    inject(name: string, register: () => unknown): unknown
    register(options: Record<string, unknown>, component: (props?: unknown) => unknown): unknown
  }
  export interface ClientContext { slots: ClientSlots }
}

declare module '@deepseek-ai/schemastery' {
  interface Schema<T> { readonly __type?: T }
  const Schema: {
    object<T extends Record<string, unknown>>(_value: T): Schema<any>
    string(): Schema<string>
  }
  export default Schema
}

declare module '@deepseek-ai/dsh-tools' {
  export function defineTool<T extends Record<string, unknown>>(value: T): T
}
