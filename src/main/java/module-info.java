/**
 * JWhisper relay server.
 */
module jwhisper.relay {
    requires static lombok;

    requires org.slf4j;
    requires tools.jackson.core;
    requires tools.jackson.databind;

    requires jwhisper.common;
}
