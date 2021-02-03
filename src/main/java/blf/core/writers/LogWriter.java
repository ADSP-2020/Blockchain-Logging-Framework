package blf.core.writers;

import blf.core.exceptions.ExceptionHandler;
import io.reactivex.annotations.NonNull;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/**
 * LogWriter
 */
public class LogWriter extends DataWriter {
    private static final Logger LOGGER = Logger.getLogger(LogWriter.class.getName());

    private final List<String> lines;

    private final ExceptionHandler exceptionHandler;

    public LogWriter() {
        this.lines = new LinkedList<>();

        this.exceptionHandler = new ExceptionHandler();
    }

    public void addLogLine(@NonNull List<Object> itemParts) {

        this.lines.add(itemParts.stream().map(this::asString).collect(Collectors.joining()));
    }

    @Override
    protected void writeState(String fileNameSuffix) {
        final String fileNameSuffixNullErrorMsg = "The suffix of the log file is null.";
        final String logLineWriteErrorMsg = "An error occurred while writing a log line into log file.";

        LOGGER.info("Log export started.");

        if (fileNameSuffix == null) {
            this.exceptionHandler.handleException(fileNameSuffixNullErrorMsg, new NullPointerException());
        }

        final Path outputPath = Paths.get(this.getOutputFolder().toString(), String.format("%s.log", fileNameSuffix));

        final File logFile = outputPath.toFile();

        try (
            final FileWriter logFileWriter = new FileWriter(logFile);
            final BufferedWriter logBufferedWriter = new BufferedWriter(logFileWriter)
        ) {

            for (String line : lines) {
                logBufferedWriter.write(line);
                logBufferedWriter.newLine();
            }

        } catch (Exception e) {
            this.exceptionHandler.handleException(logLineWriteErrorMsg, e);
        }

        LOGGER.info("Log export finished.");
    }

    @Override
    protected void deleteState() {
        this.lines.clear();
    }
}
