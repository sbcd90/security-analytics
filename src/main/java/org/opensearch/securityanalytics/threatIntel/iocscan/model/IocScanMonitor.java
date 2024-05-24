package org.opensearch.securityanalytics.threatIntel.iocscan.model;

import org.opensearch.securityanalytics.threatIntel.iocscan.dto.PerIocTypeFieldMappings;

import java.util.List;
import java.util.Map;


public class IocScanMonitor {
    String id;
    String name;
    List<PerIocTypeFieldMappings> iocTypeToIndexFieldMappings;
    Map<String, List<String>>  perIoCTypeThreatIntelIndices;

    public String getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public List<PerIocTypeFieldMappings> getIocTypeToIndexFieldMappings() {
        return iocTypeToIndexFieldMappings;
    }

    public Map<String, List<String>> getPerIoCTypeThreatIntelIndices() {
        return perIoCTypeThreatIntelIndices;
    }
}
