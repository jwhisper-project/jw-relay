/**
 * JWhisper relay server.
 */
open module jwhisper.relay {
    requires static lombok;

    requires org.slf4j;
    requires tools.jackson.core;
    requires tools.jackson.databind;
    requires spring.data.commons;
    requires spring.data.relational;
    requires spring.context;
    requires spring.boot;
    requires spring.boot.autoconfigure;
    requires spring.data.jdbc;
    requires spring.websocket;

    requires jwhisper.common;
}
