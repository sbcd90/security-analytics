package org.opensearch.securityanalytics.threatIntel.iocscan.dto;

import java.util.List;
import java.util.Map;

/**
 * DTO that contains information about an Ioc type and the list of fields in each index that map to the given
 */
public class PerIocTypeFieldMappings {

    private final String iocType;
    private final Map<String, List<String>> indexToFieldsMap;

    public PerIocTypeFieldMappings(String iocType, Map<String, List<String>> indexToFieldsMap) {
        this.iocType = iocType;
        this.indexToFieldsMap = indexToFieldsMap;
    }

    public String getIocType() {
        return iocType;
    }

    public Map<String, List<String>> getIndexToFieldsMap() {
        return indexToFieldsMap;
    }
}
