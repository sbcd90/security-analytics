package org.opensearch.securityanalytics.threatIntel.iocscan.dto;

import org.opensearch.securityanalytics.threatIntel.iocscan.model.IocScanMonitor;

import java.util.List;

public class IocScanContext<Data> {
    IocScanMonitor monitor;
    boolean dryRun;
    List<Data> data;

    public IocScanMonitor getMonitor() {
        return monitor;
    }

    public boolean isDryRun() {
        return dryRun;
    }

    public List<Data> getData() {
        return data;
    }
}
