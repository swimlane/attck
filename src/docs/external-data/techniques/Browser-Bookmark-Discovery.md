
# Browser Bookmark Discovery

## Description

### MITRE Description

> Adversaries may enumerate browser bookmarks to learn more about compromised hosts. Browser bookmarks may reveal personal information about users (ex: banking sites, interests, social media, etc.) as well as details about internal network resources such as servers, tools/dashboards, or other related infrastructure.

Browser bookmarks may also highlight additional targets after an adversary has access to valid credentials, especially [Credentials In Files](https://attack.mitre.org/techniques/T1552/001) associated with logins cached by a browser.

Specific storage locations vary based on platform and/or application, but browser bookmarks are typically stored in local files/databases.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Linux', 'Windows', 'macOS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1217

## Potential Commands

```
find / -path "*.mozilla/firefox/*/places.sqlite" 2>/dev/null -exec echo {} >> /tmp/T1217-Firefox.txt \;
cat /tmp/T1217-Firefox.txt 2>/dev/null

find / -path "*/Firefox/Profiles/*/places.sqlite" -exec echo {} >> /tmp/T1217_Firefox.txt \;
cat /tmp/T1217_Firefox.txt 2>/dev/null

find / -path "*/Google/Chrome/*/Bookmarks" -exec echo {} >> /tmp/T1217-Chrome.txt \;
cat /tmp/T1217-Chrome.txt 2>/dev/null

Get-ChildItem -Path C:\Users\ -Filter Bookmarks -Recurse -ErrorAction SilentlyContinue -Force

where /R C:\Users\ Bookmarks

where /R C:\Users\ places.sqlite

dir /s /b %USERPROFILE%\Favorites

{'darwin': {'sh': {'command': 'cat ~/Library/Application\\ Support/Google/Chrome/Default/Bookmarks\n', 'parsers': {'plugins.stockpile.app.parsers.bookmarks': [{'source': 'host.chrome.bookmark_title', 'edge': 'resolves_to', 'target': 'host.chrome.bookmark_url'}]}}}}
powershell/collection/browser_data
powershell/collection/browser_data
```

## Commands Dataset

```
[{'command': 'find / -path "*.mozilla/firefox/*/places.sqlite" 2>/dev/null '
             '-exec echo {} >> /tmp/T1217-Firefox.txt \\;\n'
             'cat /tmp/T1217-Firefox.txt 2>/dev/null\n',
  'name': None,
  'source': 'atomics/T1217/T1217.yaml'},
 {'command': 'find / -path "*/Firefox/Profiles/*/places.sqlite" -exec echo {} '
             '>> /tmp/T1217_Firefox.txt \\;\n'
             'cat /tmp/T1217_Firefox.txt 2>/dev/null\n',
  'name': None,
  'source': 'atomics/T1217/T1217.yaml'},
 {'command': 'find / -path "*/Google/Chrome/*/Bookmarks" -exec echo {} >> '
             '/tmp/T1217-Chrome.txt \\;\n'
             'cat /tmp/T1217-Chrome.txt 2>/dev/null\n',
  'name': None,
  'source': 'atomics/T1217/T1217.yaml'},
 {'command': 'Get-ChildItem -Path C:\\Users\\ -Filter Bookmarks -Recurse '
             '-ErrorAction SilentlyContinue -Force\n',
  'name': None,
  'source': 'atomics/T1217/T1217.yaml'},
 {'command': 'where /R C:\\Users\\ Bookmarks\n',
  'name': None,
  'source': 'atomics/T1217/T1217.yaml'},
 {'command': 'where /R C:\\Users\\ places.sqlite\n',
  'name': None,
  'source': 'atomics/T1217/T1217.yaml'},
 {'command': 'dir /s /b %USERPROFILE%\\Favorites\n',
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
[{'data_source': ['4663', 'File monitoring']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['API monitoring']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['API monitoring']}]
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
[{'Atomic Red Team Test - Browser Bookmark Discovery': {'atomic_tests': [{'auto_generated_guid': '3a41f169-a5ab-407f-9269-abafdb5da6c2',
                                                                          'description': 'Searches '
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
                                                                          'executor': {'cleanup_command': 'rm '
                                                                                                          '-f '
                                                                                                          '#{output_file} '
                                                                                                          '2>/dev/null\n',
                                                                                       'command': 'find '
                                                                                                  '/ '
                                                                                                  '-path '
                                                                                                  '"*.mozilla/firefox/*/places.sqlite" '
                                                                                                  '2>/dev/null '
                                                                                                  '-exec '
                                                                                                  'echo '
                                                                                                  '{} '
                                                                                                  '>> '
                                                                                                  '#{output_file} '
                                                                                                  '\\;\n'
                                                                                                  'cat '
                                                                                                  '#{output_file} '
                                                                                                  '2>/dev/null\n',
                                                                                       'name': 'sh'},
                                                                          'input_arguments': {'output_file': {'default': '/tmp/T1217-Firefox.txt',
                                                                                                              'description': 'Path '
                                                                                                                             'where '
                                                                                                                             'captured '
                                                                                                                             'results '
                                                                                                                             'will '
                                                                                                                             'be '
                                                                                                                             'placed.',
                                                                                                              'type': 'Path'}},
                                                                          'name': 'List '
                                                                                  'Mozilla '
                                                                                  'Firefox '
                                                                                  'Bookmark '
                                                                                  'Database '
                                                                                  'Files '
                                                                                  'on '
                                                                                  'Linux',
                                                                          'supported_platforms': ['linux']},
                                                                         {'auto_generated_guid': '1ca1f9c7-44bc-46bb-8c85-c50e2e94267b',
                                                                          'description': 'Searches '
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
                                                                          'executor': {'cleanup_command': 'rm '
                                                                                                          '-f '
                                                                                                          '#{output_file} '
                                                                                                          '2>/dev/null\n',
                                                                                       'command': 'find '
                                                                                                  '/ '
                                                                                                  '-path '
                                                                                                  '"*/Firefox/Profiles/*/places.sqlite" '
                                                                                                  '-exec '
                                                                                                  'echo '
                                                                                                  '{} '
                                                                                                  '>> '
                                                                                                  '#{output_file} '
                                                                                                  '\\;\n'
                                                                                                  'cat '
                                                                                                  '#{output_file} '
                                                                                                  '2>/dev/null\n',
                                                                                       'name': 'sh'},
                                                                          'input_arguments': {'output_file': {'default': '/tmp/T1217_Firefox.txt',
                                                                                                              'description': 'Path '
                                                                                                                             'where '
                                                                                                                             'captured '
                                                                                                                             'results '
                                                                                                                             'will '
                                                                                                                             'be '
                                                                                                                             'placed.',
                                                                                                              'type': 'Path'}},
                                                                          'name': 'List '
                                                                                  'Mozilla '
                                                                                  'Firefox '
                                                                                  'Bookmark '
                                                                                  'Database '
                                                                                  'Files '
                                                                                  'on '
                                                                                  'macOS',
                                                                          'supported_platforms': ['macos']},
                                                                         {'auto_generated_guid': 'b789d341-154b-4a42-a071-9111588be9bc',
                                                                          'description': 'Searches '
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
                                                                          'executor': {'cleanup_command': 'rm '
                                                                                                          '-f '
                                                                                                          '#{output_file} '
                                                                                                          '2>/dev/null\n',
                                                                                       'command': 'find '
                                                                                                  '/ '
                                                                                                  '-path '
                                                                                                  '"*/Google/Chrome/*/Bookmarks" '
                                                                                                  '-exec '
                                                                                                  'echo '
                                                                                                  '{} '
                                                                                                  '>> '
                                                                                                  '#{output_file} '
                                                                                                  '\\;\n'
                                                                                                  'cat '
                                                                                                  '#{output_file} '
                                                                                                  '2>/dev/null\n',
                                                                                       'name': 'sh'},
                                                                          'input_arguments': {'output_file': {'default': '/tmp/T1217-Chrome.txt',
                                                                                                              'description': 'Path '
                                                                                                                             'where '
                                                                                                                             'captured '
                                                                                                                             'results '
                                                                                                                             'will '
                                                                                                                             'be '
                                                                                                                             'placed.',
                                                                                                              'type': 'Path'}},
                                                                          'name': 'List '
                                                                                  'Google '
                                                                                  'Chrome '
                                                                                  'Bookmark '
                                                                                  'JSON '
                                                                                  'Files '
                                                                                  'on '
                                                                                  'macOS',
                                                                          'supported_platforms': ['macos']},
                                                                         {'auto_generated_guid': 'faab755e-4299-48ec-8202-fc7885eb6545',
                                                                          'description': 'Searches '
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
                                                                         {'auto_generated_guid': '76f71e2f-480e-4bed-b61e-398fe17499d5',
                                                                          'description': 'Searches '
                                                                                         'for '
                                                                                         'Google '
                                                                                         "Chromes's "
                                                                                         'and '
                                                                                         'Edge '
                                                                                         "Chromium's "
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
                                                                                  '/ '
                                                                                  'Edge '
                                                                                  'Chromium '
                                                                                  'Bookmarks '
                                                                                  'on '
                                                                                  'Windows '
                                                                                  'with '
                                                                                  'command '
                                                                                  'prompt',
                                                                          'supported_platforms': ['windows']},
                                                                         {'auto_generated_guid': '4312cdbc-79fc-4a9c-becc-53d49c734bc5',
                                                                          'description': 'Searches '
                                                                                         'for '
                                                                                         'Mozilla '
                                                                                         'Firefox '
                                                                                         'bookmarks '
                                                                                         'file '
                                                                                         '(on '
                                                                                         'Windows '
                                                                                         'distributions) '
                                                                                         'that '
                                                                                         'contains '
                                                                                         'bookmarks '
                                                                                         'in '
                                                                                         'a '
                                                                                         'SQLITE '
                                                                                         'database.\n'
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
                                                                                                  'places.sqlite\n',
                                                                                       'name': 'command_prompt'},
                                                                          'name': 'List '
                                                                                  'Mozilla '
                                                                                  'Firefox '
                                                                                  'bookmarks '
                                                                                  'on '
                                                                                  'Windows '
                                                                                  'with '
                                                                                  'command '
                                                                                  'prompt',
                                                                          'supported_platforms': ['windows']},
                                                                         {'auto_generated_guid': '727dbcdb-e495-4ab1-a6c4-80c7f77aef85',
                                                                          'description': 'This '
                                                                                         'test '
                                                                                         'will '
                                                                                         'list '
                                                                                         'the '
                                                                                         'bookmarks '
                                                                                         'for '
                                                                                         'Internet '
                                                                                         'Explorer '
                                                                                         'that '
                                                                                         'are '
                                                                                         'found '
                                                                                         'in '
                                                                                         'the '
                                                                                         'Favorites '
                                                                                         'folder',
                                                                          'executor': {'command': 'dir '
                                                                                                  '/s '
                                                                                                  '/b '
                                                                                                  '%USERPROFILE%\\Favorites\n',
                                                                                       'name': 'command_prompt'},
                                                                          'name': 'List '
                                                                                  'Internet '
                                                                                  'Explorer '
                                                                                  'Bookmarks '
                                                                                  'using '
                                                                                  'the '
                                                                                  'command '
                                                                                  'prompt',
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


* [Browser Bookmark Discovery Mitigation](../mitigations/Browser-Bookmark-Discovery-Mitigation.md)


# Actors

None
