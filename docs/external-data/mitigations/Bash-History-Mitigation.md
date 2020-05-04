
# Bash History Mitigation

## Description

### MITRE Description

> There are multiple methods of preventing a user's command history from being flushed to their .bash_history file, including use of the following commands:
<code>set +o history</code> and <code>set -o history</code> to start logging again;
<code>unset HISTFILE</code> being added to a user's .bash_rc file; and
<code>ln -s /dev/null ~/.bash_history</code> to write commands to <code>/dev/null</code>instead.


# Techniques


* [Bash History](../techniques/Bash-History.md)

