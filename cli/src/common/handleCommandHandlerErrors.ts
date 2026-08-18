import log from "./log";

type CommandHandler = (this: any, ...args: any[]) => any;

export default function handleCommandHandlerErrors<T extends CommandHandler>(
    commandHandler: T
): T {
    // Don't wrap the command handler when testing, to make it easier to test
    // error cases
    if (process.env.NODE_ENV === "test") {
        return commandHandler;
    }
    return async function commandHandlerWrapper(
        this: ThisParameterType<T>,
        ...args: Parameters<T>
    ) {
        try {
            return await commandHandler.apply(this, args);
        } catch (err) {
            log.error(err.message);
            process.exit(1);
        }
    } as T;
}
