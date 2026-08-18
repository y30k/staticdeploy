export default interface ILogger {
    info(message: string): void;
    error(error: unknown, message: string): void;
}
