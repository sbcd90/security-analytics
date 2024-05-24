package org.opensearch.securityanalytics.threatIntel.iocscan.model;

public class Ioc {

    private final String feedId;
    private final String iocValue;
    private final String iocType;

    public Ioc(String feedId, String iocValue, String iocType) {
        this.feedId = feedId;
        this.iocValue = iocValue;
        this.iocType = iocType;
    }

    public String getFeedId() {
        return feedId;
    }

    public String getIocValue() {
        return iocValue;
    }

    public String getIocType() {
        return iocType;
    }
}
