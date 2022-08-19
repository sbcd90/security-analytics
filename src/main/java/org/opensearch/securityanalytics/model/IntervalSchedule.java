package org.opensearch.securityanalytics.model;

import org.apache.commons.lang3.tuple.Pair;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.xcontent.XContentBuilder;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Locale;

public class IntervalSchedule extends Schedule {

    private Integer interval;

    private ChronoUnit unit;

    private transient Instant testInstant;

    private transient Long intervalInMills;

    private static final List<ChronoUnit> SUPPORTED_UNIT = List.of(ChronoUnit.MINUTES, ChronoUnit.HOURS, ChronoUnit.DAYS);

    public IntervalSchedule(Integer interval, ChronoUnit unit) {
        this.interval = interval;
        this.unit = unit;
        this.testInstant = null;

        if (!SUPPORTED_UNIT.contains(unit)) {
            throw new IllegalArgumentException(String.format(Locale.getDefault(), "Timezone %s is not supported expected %s", unit, SUPPORTED_UNIT));
        }

        if (interval <= 0) {
            throw new IllegalArgumentException("Interval is not allowed to be 0 or negative");
        }

        this.intervalInMills = Duration.of(Long.valueOf(interval), unit).toMillis();
    }

    public IntervalSchedule(StreamInput sin) throws IOException {
        this(
                sin.readInt(),
                sin.readEnum(ChronoUnit.class)
        );
    }

    public static IntervalSchedule readFrom(StreamInput sin) throws IOException {
        return new IntervalSchedule(sin);
    }

    @Override
    public Duration nextTimeToExecute(Instant enabledTime) {
        long enabledTimeEpochMillis = enabledTime.toEpochMilli();
        Instant currentTime = testInstant != null? testInstant: Instant.now();
        Long delta = currentTime.toEpochMilli() - enabledTimeEpochMillis;
        long remainingScheduleTime = intervalInMills - (delta % intervalInMills);
        return Duration.of(remainingScheduleTime, ChronoUnit.MILLIS);
    }

    @Override
    public Instant getExpectedNextExecutionTime(Instant enabledTime, Instant expectedPreviousExecutionTime) {
        long expectedPreviousExecutionTimeEpochMillis = (expectedPreviousExecutionTime != null? expectedPreviousExecutionTime: enabledTime).toEpochMilli();
        // We still need to calculate the delta even when using expectedPreviousExecutionTime because the initial value passed in
        // is the enabledTime (which also happens with cluster/node restart)
        Instant currentTime = testInstant != null? testInstant: Instant.now();
        Long delta = currentTime.toEpochMilli() - expectedPreviousExecutionTimeEpochMillis;
        // Remainder of the Delta time is how much we have already spent waiting.
        // We need to subtract remainder of that time from the interval time to get remaining schedule time to wait.
        long remainingScheduleTime = intervalInMills - (delta % intervalInMills);
        return Instant.ofEpochMilli(currentTime.toEpochMilli() + remainingScheduleTime);
    }

    @Override
    public Pair<Instant, Instant> getPeriodStartingAt(Instant startTime) {
        Instant realStartTime = startTime != null? startTime: Instant.now();
        Instant newEndTime = realStartTime.plusMillis(intervalInMills);
        return Pair.of(realStartTime, newEndTime);
    }

    @Override
    public Pair<Instant, Instant> getPeriodEndingAt(Instant endTime) {
        Instant realEndTime = endTime != null? endTime: Instant.now();
        Instant newStartTime = realEndTime.minusMillis(intervalInMills);
        return Pair.of(newStartTime, realEndTime);
    }

    @Override
    public Boolean runningOnTime(Instant lastExecutionTime) {
        if (lastExecutionTime == null) {
            return true;
        }
        return null;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeInt(interval);
        out.writeEnum(unit);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
            .startObject(PERIOD_FIELD)
            .field(INTERVAL_FIELD, interval)
            .field(UNIT_FIELD, unit.name())
            .endObject()
            .endObject();
        return builder;
    }
}