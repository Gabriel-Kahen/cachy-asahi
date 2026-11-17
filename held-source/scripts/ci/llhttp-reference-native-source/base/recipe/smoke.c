/* SPDX-License-Identifier: MIT */
#include <llhttp.h>
#include <stdio.h>
#include <string.h>
static int messages;
static int complete(llhttp_t *parser) { (void)parser; ++messages; return 0; }
int main(void) {
  llhttp_t parser;
  llhttp_settings_t settings;
  const char good[] = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
  const char bad[] = "HTTP/1.1 200 OK\r\nContent-Length: nope\r\n\r\n";
  llhttp_settings_init(&settings);
  settings.on_message_complete = complete;
  llhttp_init(&parser, HTTP_RESPONSE, &settings);
  for (size_t i = 0; i < strlen(good); ++i)
    if (llhttp_execute(&parser, good + i, 1) != HPE_OK) return 1;
  if (messages != 1 || llhttp_get_status_code(&parser) != 200 ||
      llhttp_finish(&parser) != HPE_OK) return 2;
  llhttp_init(&parser, HTTP_RESPONSE, &settings);
  if (llhttp_execute(&parser, bad, strlen(bad)) != HPE_INVALID_CONTENT_LENGTH) return 3;
  puts("llhttp: fragmented response and malformed length controls passed");
  return 0;
}
