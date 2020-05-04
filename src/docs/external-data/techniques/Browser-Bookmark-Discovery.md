
# Browser Bookmark Discovery

## Description

### MITRE Description

> Adversaries may enumerate browser bookmarks to learn more about compromised hosts. Browser bookmarks may reveal personal information about users (ex: banking sites, interests, social media, etc.) as well as details about internal network resources such as servers, tools/dashboards, or other related infrastructure.

Browser bookmarks may also highlight additional targets after an adversary has access to valid credentials, especially [Credentials in Files](https://attack.mitre.org/techniques/T1081) associated with logins cached by a browser.

Specific storage locations vary based on platform and/or application, but browser bookmarks are typically stored in local files/databases.

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User']
* Platforms: ['Linux', 'Windows', 'macOS']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1217

## Potential Commands

```
find / -path "*.mozilla/firefox/*/places.sqlite" -exec echo {} >> /tmp/firefox-bookmarks.txt \;

find / -path "*/Firefox/Profiles/*/places.sqlite" -exec echo {} >> /tmp/firefox-bookmarks.txt \;

find / -path "*/Google/Chrome/*/Bookmarks" -exec echo {} >> /tmp/chrome-bookmarks.txt \;

Get-ChildItem -Path C:\Users\ -Filter Bookmarks -Recurse -ErrorAction SilentlyContinue -Force

where /R C:\Users\ Bookmarks

{'darwin': {'sh': {'command': 'cat ~/Library/Application\\ Support/Google/Chrome/Default/Bookmarks\n', 'parsers': {'plugins.stockpile.app.parsers.bookmarks': [{'source': 'host.chrome.bookmark_title', 'edge': 'resolves_to', 'target': 'host.chrome.bookmark_url'}]}}}}
powershell/collection/browser_data
powershell/collection/browser_data
```

## Commands Dataset

```
[{'command': 'find / -path "*.mozilla/firefox/*/places.sqlite" -exec echo {} '
             '>> /tmp/firefox-bookmarks.txt \\;\n',
  'name': None,
  'source': 'atomics/T1217/T1217.yaml'},
 {'command': 'find / -path "*/Firefox/Profiles/*/places.sqlite" -exec echo {} '
             '>> /tmp/firefox-bookmarks.txt \\;\n',
  'name': None,
  'source': 'atomics/T1217/T1217.yaml'},
 {'command': 'find / -path "*/Google/Chrome/*/Bookmarks" -exec echo {} >> '
             '/tmp/chrome-bookmarks.txt \\;\n',
  'name': None,
  'source': 'atomics/T1217/T1217.yaml'},
 {'command': 'Get-ChildItem -Path C:\\Users\\ -Filter Bookmarks -Recurse '
             '-ErrorAction SilentlyContinue -Force\n',
  'name': None,
  'source': 'atomics/T1217/T1217.yaml'},
 {'command': 'where /R C:\\Users\\ Bookmarks\n',
  'name': None,
  'source': 'atomics/T1217/T1217.yaml'},
 {'command': {'darwin': {'sh': {'command': 'cat ~/Library/Application\\ '
                                           'Support/Google/Chrome/Default/Bookmarks\n',
                                'parsers': {'plugins.stockpile.app.parsers.bookmarks': [{'edge': 'resolves_to',
                                                                                         'source': 'host.chrome.bookmark_title',
                                                                                         'target': 'host.chrome.bookmark_url'}]}}}},
  'name': 'Get Chrome Bookmarks',
  'source': 'data/abilities/discovery/b007fc38-9eb7-4320-92b3-9a3ad3e6ec25.yml'},
 {'command': 'powershell/collection/browser_data',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/collection/browser_data',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json

```

## Potential Queries

```json
[{'name': 'Browser Bookmark Discovery',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1and (process_command_line contains '
           '"*firefox*places.sqlite*")'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Browser Bookmark Discovery': {'atomic_tests': [{'description': 'Searches '
                                                                                         'for '
                                                                                         'Mozilla '
                                                                                         "Firefox's "
                                                                                         'places.sqlite '
                                                                                         'file '
                                                                                         '(on '
                                                                                         'Linux '
                                                                                         'distributions) '
                                                                                         'that '
                                                                                         'contains '
                                                                                         'bookmarks '
                                                                                         'and '
                                                                                         'lists '
                                                                                         'any '
                                                                                         'found '
                                                                                         'instances '
                                                                                         'to '
                                                                                         'a '
                                                                                         'text '
                                                                                         'file.\n',
                                                                          'executor': {'command': 'find '
                                                                                                  '/ '
                                                                                                  '-path '
                                                                                                  '"*.mozilla/firefox/*/places.sqlite" '
                                                                                                  '-exec '
                                                                                                  'echo '
                                                                                                  '{} '
                                                                                                  '>> '
                                                                                                  '/tmp/firefox-bookmarks.txt '
                                                                                                  '\\;\n',
                                                                                       'name': 'sh'},
                                                                          'name': 'List '
                                                                                  'Mozilla '
                                                                                  'Firefox '
                                                                                  'Bookmark '
                                                                                  'Database '
                                                                                  'Files '
                                                                                  'on '
                                                                                  'Linux',
                                                                          'supported_platforms': ['linux']},
                                                                         {'description': 'Searches '
                                                                                         'for '
                                                                                         'Mozilla '
                                                                                         "Firefox's "
                                                                                         'places.sqlite '
                                                                                         'file '
                                                                                         '(on '
                                                                                         'macOS) '
                                                                                         'that '
                                                                                         'contains '
                                                                                         'bookmarks '
                                                                                         'and '
                                                                                         'lists '
                                                                                         'any '
                                                                                         'found '
                                                                                         'instances '
                                                                                         'to '
                                                                                         'a '
                                                                                         'text '
                                                                                         'file.\n',
                                                                          'executor': {'command': 'find '
                                                                                                  '/ '
                                                                                                  '-path '
                                                                                                  '"*/Firefox/Profiles/*/places.sqlite" '
                                                                                                  '-exec '
                                                                                                  'echo '
                                                                                                  '{} '
                                                                                                  '>> '
                                                                                                  '/tmp/firefox-bookmarks.txt '
                                                                                                  '\\;\n',
                                                                                       'name': 'sh'},
                                                                          'name': 'List '
                                                                                  'Mozilla '
                                                                                  'Firefox '
                                                                                  'Bookmark '
                                                                                  'Database '
                                                                                  'Files '
                                                                                  'on '
                                                                                  'macOS',
                                                                          'supported_platforms': ['macos']},
                                                                         {'description': 'Searches '
                                                                                         'for '
                                                                                         'Google '
                                                                                         "Chrome's "
                                                                                         'Bookmark '
                                                                                         'file '
                                                                                         '(on '
                                                                                         'macOS) '
                                                                                         'that '
                                                                                         'contains '
                                                                                         'bookmarks '
                                                                                         'in '
                                                                                         'JSON '
                                                                                         'format '
                                                                                         'and '
                                                                                         'lists '
                                                                                         'any '
                                                                                         'found '
                                                                                         'instances '
                                                                                         'to '
                                                                                         'a '
                                                                                         'text '
                                                                                         'file.\n',
                                                                          'executor': {'command': 'find '
                                                                                                  '/ '
                                                                                                  '-path '
                                                                                                  '"*/Google/Chrome/*/Bookmarks" '
                                                                                                  '-exec '
                                                                                                  'echo '
                                                                                                  '{} '
                                                                                                  '>> '
                                                                                                  '/tmp/chrome-bookmarks.txt '
                                                                                                  '\\;\n',
                                                                                       'name': 'sh'},
                                                                          'name': 'List '
                                                                                  'Google '
                                                                                  'Chrome '
                                                                                  'Bookmark '
                                                                                  'JSON '
                                                                                  'Files '
                                                                                  'on '
                                                                                  'macOS',
                                                                          'supported_platforms': ['macos']},
                                                                         {'description': 'Searches '
                                                                                         'for '
                                                                                         'Google '
                                                                                         "Chromes's "
                                                                                         'Bookmarks '
                                                                                         'file '
                                                                                         '(on '
                                                                                         'Windows '
                                                                                         'distributions) '
                                                                                         'that '
                                                                                         'contains '
                                                                                         'bookmarks.\n'
                                                                                         'Upon '
                                                                                         'execution, '
                                                                                         'paths '
                                                                                         'that '
                                                                                         'contain '
                                                                                         'bookmark '
                                                                                         'files '
                                                                                         'will '
                                                                                         'be '
                                                                                         'displayed.\n',
                                                                          'executor': {'command': 'Get-ChildItem '
                                                                                                  '-Path '
                                                                                                  'C:\\Users\\ '
                                                                                                  '-Filter '
                                                                                                  'Bookmarks '
                                                                                                  '-Recurse '
                                                                                                  '-ErrorAction '
                                                                                                  'SilentlyContinue '
                                                                                                  '-Force\n',
                                                                                       'name': 'powershell'},
                                                                          'name': 'List '
                                                                                  'Google '
                                                                                  'Chrome '
                                                                                  'Bookmarks '
                                                                                  'on '
                                                                                  'Windows '
                                                                                  'with '
                                                                                  'powershell',
                                                                          'supported_platforms': ['windows']},
                                                                         {'description': 'Searches '
                                                                                         'for '
                                                                                         'Google '
                                                                                         "Chromes's "
                                                                                         'Bookmarks '
                                                                                         'file '
                                                                                         '(on '
                                                                                         'Windows '
                                                                                         'distributions) '
                                                                                         'that '
                                                                                         'contains '
                                                                                         'bookmarks.\n'
                                                                                         'Upon '
                                                                                         'execution, '
                                                                                         'paths '
                                                                                         'that '
                                                                                         'contain '
                                                                                         'bookmark '
                                                                                         'files '
                                                                                         'will '
                                                                                         'be '
                                                                                         'displayed.\n',
                                                                          'executor': {'command': 'where '
                                                                                                  '/R '
                                                                                                  'C:\\Users\\ '
                                                                                                  'Bookmarks\n',
                                                                                       'name': 'command_prompt'},
                                                                          'name': 'List '
                                                                                  'Google '
                                                                                  'Chrome '
                                                                                  'Bookmarks '
                                                                                  'on '
                                                                                  'Windows '
                                                                                  'with '
                                                                                  'command '
                                                                                  'prompt.',
                                                                          'supported_platforms': ['windows']}],
                                                        'attack_technique': 'T1217',
                                                        'display_name': 'Browser '
                                                                        'Bookmark '
                                                                        'Discovery'}},
 {'Mitre Stockpile - Get Chrome Bookmarks': {'description': 'Get Chrome '
                                                            'Bookmarks',
                                             'id': 'b007fc38-9eb7-4320-92b3-9a3ad3e6ec25',
                                             'name': 'Get Chrome Bookmarks',
                                             'platforms': {'darwin': {'sh': {'command': 'cat '
                                                                                        '~/Library/Application\\ '
                                                                                        'Support/Google/Chrome/Default/Bookmarks\n',
                                                                             'parsers': {'plugins.stockpile.app.parsers.bookmarks': [{'edge': 'resolves_to',
                                                                                                                                      'source': 'host.chrome.bookmark_title',
                                                                                                                                      'target': 'host.chrome.bookmark_url'}]}}}},
                                             'tactic': 'discovery',
                                             'technique': {'attack_id': 'T1217',
                                                           'name': 'Browser '
                                                                   'Bookmark '
                                                                   'Discovery'}}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1217',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/collection/browser_data":  '
                                                                                 '["T1217"],',
                                            'Empire Module': 'powershell/collection/browser_data',
                                            'Technique': 'Browser Bookmark '
                                                         'Discovery'}}]
```

# Tactics


* [Discovery](../tactics/Discovery.md)


# Mitigations

None

# Actors

None
