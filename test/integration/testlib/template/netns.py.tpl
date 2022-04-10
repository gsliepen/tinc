    # Indentation is important! This gets copied inside another Python script.
    import subprocess as subp

    iface = os.environ['INTERFACE']
    log.info('using interface %s', iface)

    subp.run(['ip', 'link', 'set', 'dev', iface, 'netns', '$NAMESPACE'], check=True)
    subp.run(['ip', 'netns', 'exec', '$NAMESPACE', 'ip', 'addr', 'add', '$ADDRESS/$MASK', 'dev', iface], check=True)
    subp.run(['ip', 'netns', 'exec', '$NAMESPACE', 'ip', 'link', 'set', iface, 'up'], check=True)
