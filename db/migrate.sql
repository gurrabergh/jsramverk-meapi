CREATE TABLE IF NOT EXISTS users (
    email VARCHAR(255) NOT NULL,
    password VARCHAR(60) NOT NULL,
    UNIQUE(email)
);

BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS "texts" (
	"id"	INTEGER NOT NULL,
	"heading"	TEXT,
	"content"	TEXT NOT NULL,
	PRIMARY KEY("id" AUTOINCREMENT)
);
INSERT INTO "texts" ("id","heading","content") VALUES (1,'<h1>Hem<h1>','<p>Hej! Jag heter Gustav Berg och är 23 år gammal. Född och uppvuxen i Umeå där jag fortfarande bor kvar. Jag tog studenten från Teknikprogrammet 2015 och har sedan dess jobbat på ett Ica Kvantum. Har även testat att läsa några månader på Teknisk Datavetenskap (Civilingenjör) men det kändes inte helt rätt.</p>
<p>På min fritid så spenderar jag mycket tid på att spela ishockey då jag är målvakt i Division 2. Annars så gillar jag att styrketräna, spela datorspel, käka hamburgare eller bara att ta det lugnt i soffan framför Netflix.</p>
<p>Jag har alltid gillat problemlösning och jag läste ett par kurser programmering på gymnasiet. Av en slump så hittade jag hemsidan till BTH''s utbildning "Webbprogrammering" och efter lite efterforskningar så verkade det vara en bra utbildning. Nu ser jag fram emot att lära mig massor under de kommande två åren.</p>');
INSERT INTO "texts" ("id","heading","content") VALUES (2,'<h1 id="mesida">mesida</h1>','<p>Här är <a href="https://github.com/gurrabergh/jsramverk-frontend">GitHub-repot</a> för denna sida.</p>
  <h2 id="project-setup">Project setup</h2>
  <pre><code>npm <span class="hljs-keyword">install</span>
  </code></pre><h3 id="compiles-and-hot-reloads-for-development">Compiles and hot-reloads for development</h3>
  <pre><code>npm <span class="hljs-keyword">run</span><span class="bash"> serve</span>
  </code></pre><h3 id="compiles-and-minifies-for-production">Compiles and minifies for production</h3>
  <pre><code>npm <span class="hljs-keyword">run</span><span class="bash"> build</span>
  </code></pre><h3 id="lints-and-fixes-files">Lints and fixes files</h3>
  <pre><code>npm <span class="hljs-keyword">run</span><span class="bash"> lint</span>
  </code></pre><h3 id="customize-configuration">Customize configuration</h3>
  <p>See <a href="https://cli.vuejs.org/config/">Configuration Reference</a>.</p>');
  INSERT INTO "texts" ("id","heading","content") VALUES (3,'test','test');
INSERT INTO "texts" ("id","heading","content") VALUES (4,'<h1 id="mesida">me-api</h1>','<p>Här är <a href="https://github.com/gurrabergh/jsramverk-meapi">GitHub-repot</a> för denna sida.</p>

  <h2 id="project-setup">Project setup</h2>

  <pre><code>npm <span class="hljs-keyword">install</span>

  </code></pre><h3 id="compiles-and-hot-reloads-for-development">Compiles and hot-reloads for development</h3>

  <pre><code>npm <span class="bash"> start</span>

  </code></pre><h3 id="compiles-and-minifies-for-production">Compiles and minifies for production</h3>

  <pre><code>npm <span class="hljs-keyword">run</span><span class="bash"> production</span>

  </code></pre>');
COMMIT;
