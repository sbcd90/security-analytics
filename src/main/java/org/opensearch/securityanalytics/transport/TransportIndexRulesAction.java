/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.ActionListener;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.client.Client;
import org.opensearch.common.inject.Inject;
import org.opensearch.rest.RestStatus;
import org.opensearch.securityanalytics.action.IndexRulesAction;
import org.opensearch.securityanalytics.action.IndexRulesRequest;
import org.opensearch.securityanalytics.action.IndexRulesResponse;
import org.opensearch.securityanalytics.rules.backend.OSQueryBackend;
import org.opensearch.securityanalytics.rules.backend.QueryBackend;
import org.opensearch.securityanalytics.rules.exceptions.SigmaError;
import org.opensearch.securityanalytics.rules.objects.SigmaRule;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.nio.file.*;
import java.util.*;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class TransportIndexRulesAction extends HandledTransportAction<IndexRulesRequest, IndexRulesResponse> {

    private static final Logger log = LogManager.getLogger(TransportIndexRulesAction.class);

    private final Client client;

    @Inject
    public TransportIndexRulesAction(TransportService transportService, Client client, ActionFilters actionFilters) {
        super(IndexRulesAction.NAME, transportService, actionFilters, IndexRulesRequest::new);
        this.client = client;
    }

    @Override
    protected void doExecute(Task task, IndexRulesRequest request, ActionListener<IndexRulesResponse> actionListener) {
        log.info("hit securityanalytics");
        importRules(client, actionListener, request);
    }

    private void importRules(Client client, ActionListener<IndexRulesResponse> actionListener, IndexRulesRequest request) {
        try {
            final String url = Objects.requireNonNull(getClass().getClassLoader().getResource("rules/")).toURI().toString();
            Path path;
            if (url.contains("!")) {
                final Map<String, String> env = new HashMap<>();
                final String[] array = url.split("!");
                final FileSystem fs = FileSystems.newFileSystem(URI.create(array[0]), env);
                path = fs.getPath(array[1]);
            } else {
                path = Path.of(url);
            }

            Stream<Path> folder = Files.list(path);

            List<String> rules = getRules(folder.collect(Collectors.toList()));

            for (String ruleStr: rules) {
                SigmaRule rule = SigmaRule.fromYaml(ruleStr, true);

                QueryBackend backend = new OSQueryBackend(true, false);
                List<Object> queries = backend.convertRule(rule);
                log.info(queries.get(0).toString());
            }
            actionListener.onResponse(new IndexRulesResponse(RestStatus.CREATED));
        } catch (URISyntaxException | IOException | SigmaError ex) {
            actionListener.onFailure(ex);
        }
    }

    private List<String> getRules(List<Path> listOfRules) {
        List<String> rules = new ArrayList<>();

        listOfRules.forEach(new Consumer<Path>() {
            @Override
            public void accept(Path path) {
                try {
                    if (Files.isDirectory(path)) {
                        rules.addAll(getRules(Files.list(path).collect(Collectors.toList())));
                    } else {
                        rules.add(Files.readString(path, Charset.defaultCharset()));
                    }
                } catch (IOException ex) {
                    // suppress with log
                    log.warn("rules cannot be parsed");
                }
            }
        });
        return rules;
    }
}