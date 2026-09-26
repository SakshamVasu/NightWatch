/* Nmap format adapters. Add another adapter here and return the common report shape. */
(function (root) {
  'use strict';
  const clean = s => (s || '').replace(/\x1b\[[0-9;]*m/g, '').trim();
  const makeHost = (address, hostname) => ({ address: address || 'Unknown host', hostname: hostname || '', state: 'unknown', ports: [], os: [], network: [], scripts: [], notes: [] });
  function parseNormal(raw) {
    const lines = raw.split(/\r?\n/).map(clean), hosts = [], byAddr = new Map();
    let current = null;
    const hostFor = (addr, name) => {
      let h = byAddr.get(addr);
      if (!h) { h = makeHost(addr, name); byAddr.set(addr, h); hosts.push(h); }
      else if (name && !h.hostname) h.hostname = name;
      return h;
    };
    for (const line of lines) {
      let m;
      if ((m = line.match(/^Nmap scan report for (.+)$/i))) {
        const who = m[1], ip = who.match(/\(([^)]+)\)$/), addr = ip ? ip[1] : who;
        const hostName = ip ? who.slice(0, who.lastIndexOf(' (')) : '';
        current = hostFor(addr, hostName); continue;
      }
      if ((m = line.match(/^Host is (up|down)(?:\s*\((.*)\))?/i))) { if (current) { current.state = m[1].toLowerCase(); if (m[2]) current.notes.push(m[2]); } continue; }
      if ((m = line.match(/^PORT\s+STATE\s+SERVICE(?:\s+VERSION)?/i))) continue;
      if ((m = line.match(/^(\d+)\/(tcp|udp)\s+(\S+)\s+(\S+)(?:\s+(.*))?$/i))) {
        if (current) current.ports.push({ port: Number(m[1]), protocol: m[2].toLowerCase(), state: m[3], service: m[4], version: (m[5] || '').trim(), scripts: [] }); continue;
      }
      if ((m = line.match(/^\|_?\s*([^:]+):\s*(.*)$/))) { if (current) current.scripts.push({ name: m[1].trim(), output: m[2].trim() }); continue; }
      if ((m = line.match(/^\|\s+(.+)$/))) { if (current?.scripts.length) current.scripts.at(-1).output += '\n' + m[1]; continue; }
      if ((m = line.match(/^Service Info:\s*(.*)$/i))) { if (current) current.network.push({ label: 'Service info', value: m[1] }); continue; }
      if ((m = line.match(/^OS details?:\s*(.*)$/i))) { if (current) current.os.push(m[1]); continue; }
      if ((m = line.match(/^Running:\s*(.*)$/i))) { if (current) current.os.push(m[1]); continue; }
      if ((m = line.match(/^Aggressive OS guesses:\s*(.*)$/i))) { if (current) current.os.push('Aggressive guesses: ' + m[1]); continue; }
      if ((m = line.match(/^MAC Address:\s*(.*)$/i))) { if (current) current.network.push({ label: 'MAC address', value: m[1] }); continue; }
      if ((m = line.match(/^Network Distance:\s*(.*)$/i))) { if (current) current.network.push({ label: 'Network distance', value: m[1] }); continue; }
      if ((m = line.match(/^TRACEROUTE\s*(.*)$/i))) { if (current) current.network.push({ label: 'Traceroute', value: m[1] }); continue; }
      if ((m = line.match(/^HOP\s+RTT\s+ADDRESS/i))) continue;
      if ((m = line.match(/^\s*\d+\s+([\d.]+\s+ms\s+)?(.+)$/)) && current && lines.some(x => /^TRACEROUTE/i.test(x))) { current.network.push({ label: 'Route hop', value: m[2] }); continue; }
    }
    return { hosts, lines };
  }
  function parseGrepable(raw) {
    const hosts = [], byAddr = new Map(), lines = raw.split(/\r?\n/).map(clean);
    for (const line of lines) {
      const m = line.match(/^Host:\s+(\S+)(?:\s+\((.*?)\))?\s+\t?Status:\s+(\w+)(?:\s+\t?Ports:\s+(.*))?/i); if (!m) continue;
      const h = makeHost(m[1], m[2]); h.state = m[3].toLowerCase(); byAddr.set(h.address, h); hosts.push(h);
      for (const p of (m[4] || '').split(',\s*')) { const pm = p.match(/(\d+)\/(open|closed|filtered)\/(tcp|udp)\/([^/]*)\/([^/]*)/i); if (pm) h.ports.push({ port: +pm[1], state: pm[2], protocol: pm[3], service: pm[4], version: pm[5], scripts: [] }); }
    }
    return { hosts, lines };
  }
  function parseXml(raw) {
    const doc = new DOMParser().parseFromString(raw, 'application/xml'); if (doc.querySelector('parsererror')) throw Error('This file does not appear to be valid Nmap XML.');
    const hosts = [...doc.querySelectorAll('host')].map(el => {
      const addr = el.querySelector('address[addrtype="ipv4"],address[addrtype="ipv6"],address')?.getAttribute('addr') || 'Unknown host';
      const h = makeHost(addr, el.querySelector('hostname')?.getAttribute('name')); h.state = el.querySelector('status')?.getAttribute('state') || 'unknown';
      h.ports = [...el.querySelectorAll('ports > port')].map(p => ({ port: +p.getAttribute('portid'), protocol: p.getAttribute('protocol'), state: p.querySelector('state')?.getAttribute('state') || 'unknown', service: p.querySelector('service')?.getAttribute('name') || 'unknown', version: [p.querySelector('service')?.getAttribute('product'), p.querySelector('service')?.getAttribute('version'), p.querySelector('service')?.getAttribute('extrainfo')].filter(Boolean).join(' '), scripts: [...p.querySelectorAll('script')].map(s => ({ name: s.getAttribute('id'), output: s.getAttribute('output') || '' })) }));
      h.scripts = [...el.querySelectorAll(':scope > hostscript > script')].map(s => ({ name: s.getAttribute('id'), output: s.getAttribute('output') || '' }));
      h.os = [...el.querySelectorAll('osmatch')].map(x => `${x.getAttribute('name')} (accuracy ${x.getAttribute('accuracy')}%)`);
      h.network = [...el.querySelectorAll('address[addrtype="mac"]')].map(x => ({ label: 'MAC address', value: [x.getAttribute('addr'), x.getAttribute('vendor')].filter(Boolean).join(' · ') }));
      return h;
    });
    return { hosts, lines: raw.split(/\r?\n/) };
  }
  function parse(raw, filename = 'scan.txt') {
    const ext = filename.toLowerCase().split('.').pop(); let format = 'normal', parsed;
    if (ext === 'xml' || /^\s*<\?xml|^\s*<nmaprun/i.test(raw)) { format = 'xml'; parsed = parseXml(raw); }
    else if (ext === 'gnmap' || /^Host:\s/im.test(raw)) { format = 'grepable'; parsed = parseGrepable(raw); }
    else { parsed = parseNormal(raw); }
    const hosts = parsed.hosts;
    const scripts = hosts.flatMap(h => [...h.scripts.map(s => ({ ...s, host: h.address })), ...h.ports.flatMap(p => p.scripts.map(s => ({ ...s, host: h.address, port: p.port })))]);
    const findings = scripts.flatMap(s => {
      const result = [], text = `${s.name} ${s.output}`;
      const explicit = /\b(VULNERABLE|VULNERABILITY|EXPLOITABLE)\b/i.test(text);
      const severity = /\bCRITICAL\b/i.test(text) ? 'critical' : /\bHIGH\b/i.test(text) ? 'high' : /\bMEDIUM\b/i.test(text) ? 'medium' : /\bLOW\b/i.test(text) ? 'low' : 'info';
      if (explicit) result.push({ kind: 'reported', severity, title: s.name, description: s.output, host: s.host, port: s.port });
      return result;
    });
    const web = scripts.filter(s => /http|ssl|tls|http-title|robots|http-enum|http-methods|http-headers/i.test(s.name) || /https?:\/\//i.test(s.output));
    const allText = parsed.lines.join('\n');
    const unparsed = parsed.lines.filter(l => l.trim() && !/^(Starting Nmap|Nmap scan report for|Host is |PORT\s+STATE|\d+\/(tcp|udp)\s|Service Info:|OS details?:|Running:|Aggressive OS guesses:|MAC Address:|Network Distance:|TRACEROUTE|HOP\s+RTT|Nmap done:|Not shown:|All \d+ scanned ports|No exact OS matches|OS and Service detection performed|Read data files from:|Initiating |Completed |Skipping |NSE:|\|)/i.test(l));
    const date = (allText.match(/Starting Nmap .*?\((.*?)\)/i) || [])[1] || '';
    const duration = (allText.match(/Nmap done:.*?scanned in ([^.]+ seconds?)/i) || [])[1] || '';
    return { format, raw, filename, hosts, findings, scripts, web, unparsed, scan: { date, duration, hostCount: hosts.length, upCount: hosts.filter(h => h.state === 'up').length, openCount: hosts.reduce((n,h) => n + h.ports.filter(p => p.state === 'open').length, 0), portCount: hosts.reduce((n,h) => n + h.ports.length, 0), command: (allText.match(/^(?:sudo )?nmap\s.+$/im) || [])[0] || '' } };
  }
  root.NmapParser = { parse };
})(window);
