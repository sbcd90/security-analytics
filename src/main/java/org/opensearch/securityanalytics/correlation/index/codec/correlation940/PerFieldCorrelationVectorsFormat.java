/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.correlation.index.codec.correlation940;

import org.apache.lucene.codecs.lucene94.Lucene94HnswVectorsFormat;
import org.opensearch.index.mapper.MapperService;
import org.opensearch.securityanalytics.correlation.index.codec.BasePerFieldCorrelationVectorsFormat;

import java.util.Optional;

public class PerFieldCorrelationVectorsFormat extends BasePerFieldCorrelationVectorsFormat {

    public PerFieldCorrelationVectorsFormat(final Optional<MapperService> mapperService) {
        super(
                mapperService,
                Lucene94HnswVectorsFormat.DEFAULT_MAX_CONN,
                Lucene94HnswVectorsFormat.DEFAULT_BEAM_WIDTH,
                () -> new Lucene94HnswVectorsFormat(),
                (maxConn, beamWidth) -> new Lucene94HnswVectorsFormat(maxConn, beamWidth)
        );
    }
}