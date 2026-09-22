/*
 * End-of-life marker for retired image tags.
 *
 * Installed as both /bin/sh and the entrypoint of a scratch image that is
 * pushed over a retired tag. Any RUN step in a consumer's build and any
 * `docker run` therefore stops here with an explanation and the replacement
 * image, instead of silently continuing on an image that no longer receives
 * security fixes.
 *
 * The message is baked into /etc/eol-message at build time (see Dockerfile),
 * so one binary serves every retired tag.
 */
#include <stdio.h>

int main(void)
{
    FILE *message = fopen("/etc/eol-message", "r");
    int c;

    if (message == NULL) {
        fputs("This image has reached end of life and must not be used.\n",
              stderr);
        return 1;
    }
    while ((c = fgetc(message)) != EOF) {
        fputc(c, stderr);
    }
    fclose(message);
    return 1;
}
