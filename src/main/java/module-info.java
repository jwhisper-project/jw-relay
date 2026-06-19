/**
 * JWhisper relay server.
 */
module jwhisper.relay {
    requires static lombok;

    requires org.slf4j;
    requires tools.jackson.core;
    requires tools.jackson.databind;
    requires spring.data.commons;
    requires spring.data.relational;

    requires jwhisper.common;
}
