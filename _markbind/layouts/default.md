<head-bottom>
<link rel="stylesheet" href="{{baseUrl}}/stylesheets/main.css">
<link rel="stylesheet" href="{{baseUrl}}/stylesheets/study.css">
</head-bottom>

<header sticky>
<navbar type="dark" default-highlight-on="exact">
<a slot="brand" href="{{baseUrl}}/index.html" class="navbar-brand">CS3235 notes</a>
<li><a href="{{baseUrl}}/memory_vulnerabilities/README.html" class="nav-link">Memory safety</a></li>
<li><a href="{{baseUrl}}/part2/webbook-7-12/README.html" class="nav-link">Sandboxing to cryptography</a></li>
<li slot="right"><form class="navbar-form" role="search"><searchbar :data="searchData" :on-hit="searchCallback" placeholder="Search notes" menu-align-right></searchbar></form></li>
<dark-mode-toggle slot="right" />
</navbar>
</header>

<div id="flex-body">
<nav id="site-nav" aria-label="Chapters">
<div class="site-nav-top">Course notes</div>
<div class="nav-component slim-scroll">
<site-nav>
* [Overview]({{baseUrl}}/index.html)
* Memory safety :expanded:
  * [0. Introduction]({{baseUrl}}/memory_vulnerabilities/introduction-0.html)
  * [1A/1B. Spatial errors]({{baseUrl}}/memory_vulnerabilities/spatial-1a1b.html)
  * [2. Temporal errors]({{baseUrl}}/memory_vulnerabilities/temporal-2.html)
  * [3. Memory exploits]({{baseUrl}}/memory_vulnerabilities/exploits-3.html)
  * [4. Partial safety]({{baseUrl}}/memory_vulnerabilities/partial-safety-4.html)
  * [5. Full safety]({{baseUrl}}/memory_vulnerabilities/full-safety-5.html)
  * [6. Rust]({{baseUrl}}/memory_vulnerabilities/rust-6.html)
* Sandboxing and isolation :expanded:
  * [7. Sandboxing]({{baseUrl}}/part2/webbook-7-12/07-sandboxing.html)
  * [8. Policies]({{baseUrl}}/part2/webbook-7-12/08-policies.html)
  * [9. Capabilities]({{baseUrl}}/part2/webbook-7-12/09-capabilities.html)
  * [10. Virtual machines]({{baseUrl}}/part2/webbook-7-12/10-virtual-machines.html)
  * [11. Trusted execution environments]({{baseUrl}}/part2/webbook-7-12/11-tee.html)
  * [12. Cryptography]({{baseUrl}}/part2/webbook-7-12/12-cryptography.html)
* Revision :expanded:
  * [Memory safety cheatsheet]({{baseUrl}}/memory_vulnerabilities/cheatsheet.html)
  * [Review checkpoints]({{baseUrl}}/memory_vulnerabilities/review-checkpoints.html)
  * [Topics 7 to 12 index]({{baseUrl}}/part2/webbook-7-12/INDEX.html)
  * [Prerequisites]({{baseUrl}}/memory_vulnerabilities/prerequisites.html)
  * [Assignment]({{baseUrl}}/memory_vulnerabilities/assignment-overview.html)
* Original sketches
  * [C basics]({{baseUrl}}/memory_vulnerabilities/c_basics.html)
  * [Spatial]({{baseUrl}}/memory_vulnerabilities/spatial.html)
  * [Temporal]({{baseUrl}}/memory_vulnerabilities/temporal.html)
  * [Sandboxing]({{baseUrl}}/part2/2a.html)
</site-nav>
</div>
</nav>
<main id="content-wrapper">
<breadcrumb />
{{ content }}
</main>
<nav id="page-nav" aria-label="On this page"><div class="nav-component slim-scroll"><page-nav /></div></nav>
<scroll-top-button />
</div>
<footer><div class="text-center"><small>CS3235 study notes. Built with <a href="https://markbind.org/">MarkBind</a>.</small></div></footer>
