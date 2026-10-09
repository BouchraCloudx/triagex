"""Rapport HTML lisible dans Jenkins.

Jenkins applique une politique de sécurité (CSP) qui bloque le CSS et le JavaScript des
rapports publiés. On n'utilise donc que des attributs HTML (border, bgcolor...), que la CSP
n'interdit pas : le rapport reste lisible sans affaiblir la sécurité de Jenkins.
"""
from jinja2 import Environment

COLORS = {
    "critique": "#f5b7b1", "haute": "#f9d79f", "moyenne": "#fcf3cf",
    "basse": "#d6eaf8",
}
VERDICTS = {
    "true_positive": "Vrai positif", "false_positive": "Faux positif",
    "needs_review": "À vérifier", None: "Non analysé",
}
MAX_LOW_ROWS = 150

TEMPLATE = """<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8"><title>Rapport TriageX</title></head>
<body>
<h1>Rapport TriageX{% if build %} &mdash; build #{{ build }}{% endif %}</h1>

<table border="0" cellpadding="10" width="100%"><tr>
<td bgcolor="{{ '#d5f5e3' if gate.passed else '#f5b7b1' }}">
<font size="5"><b>Quality gate : {{ 'VALIDÉ' if gate.passed else 'BLOQUÉ' }}</b></font><br>
{{ gate.rule }}
{% if gate.blocking %}<br><b>Alertes bloquantes :</b> {{ gate.blocking | join(', ') }}{% endif %}
</td></tr></table>

<h2>Avant / après le triage IA</h2>
<table border="1" cellpadding="6" cellspacing="0">
<tr bgcolor="#eaecee"><th align="left">Mesure</th><th align="right">Valeur</th></tr>
<tr><td>Alertes brutes des scanners</td><td align="right"><b>{{ s.raw_total }}</b></td></tr>
<tr><td>Alertes uniques après déduplication</td><td align="right">{{ s.unique_total }}</td></tr>
<tr><td>Alertes à traiter (critiques + hautes)</td><td align="right"><b>{{ s.actionable }}</b></td></tr>
<tr><td>Réduction du nombre d'alertes à traiter</td><td align="right"><b>{{ s.reduction_percent }} %</b></td></tr>
<tr><td>Alertes de code analysées par l'IA ({{ s.model }})</td><td align="right">{{ s.ai_analyzed }}</td></tr>
<tr><td>Confirmées / contestées / indécises</td><td align="right">{{ s.ai_confirmed }} / {{ s.ai_contested }} / {{ s.ai_undecided }}</td></tr>
<tr><td>Durée du triage</td><td align="right">{{ s.duration_seconds }} s</td></tr>
</table>

<h2>Répartition par priorité</h2>
<table border="1" cellpadding="6" cellspacing="0"><tr>
{% for p, n in s.by_priority.items() %}<td bgcolor="{{ colors[p] }}" align="center"><b>{{ p }}</b><br>{{ n }}</td>{% endfor %}
</tr></table>

<h2>Alertes à traiter en priorité</h2>
{% if top %}
<table border="1" cellpadding="6" cellspacing="0" width="100%">
<tr bgcolor="#eaecee"><th>ID</th><th>Priorité</th><th>Score</th><th>Alerte</th><th>Emplacement</th><th>Analyse IA</th><th>Correctif proposé</th></tr>
{% for f in top %}
<tr bgcolor="{{ colors[f.priority] }}" valign="top">
<td>{{ f.id }}</td><td><b>{{ f.priority }}</b></td><td align="right">{{ f.score }}</td>
<td><b>{{ f.title }}</b><br><small>{{ f.tool }} &middot; {{ f.rule_id }}{% if f.epss is not none %} &middot; EPSS {{ '%.3f' | format(f.epss) }}{% endif %}{% if f.kev %} &middot; <b>KEV</b>{% endif %}</small>
{% for n in f.notes %}<br><small><i>{{ n }}</i></small>{% endfor %}</td>
<td>{% if f.file %}{{ f.file }}:{{ f.line }}{% else %}{{ f.packages | join(', ') }} {{ f.installed_version or '' }}{% endif %}</td>
<td>{{ verdicts[f.ai_verdict] }}{% if f.ai_confidence is not none %} ({{ (f.ai_confidence * 100) | round | int }} %){% endif %}<br><small>{{ f.ai_explanation }}</small></td>
<td>{{ f.ai_fix or (('Mettre à jour vers ' ~ f.fixed_version) if f.fixed_version else '') }}</td>
</tr>
{% endfor %}
</table>
{% else %}<p>Aucune alerte critique ou haute.</p>{% endif %}

<h2>Alertes contestées par l'IA (à vérifier en priorité)</h2>
{% if contested %}
<table border="1" cellpadding="6" cellspacing="0" width="100%">
<tr bgcolor="#eaecee"><th>ID</th><th>Priorité</th><th>Alerte</th><th>Emplacement</th><th>Avis de l'IA</th></tr>
{% for f in contested %}<tr valign="top" bgcolor="{{ colors[f.priority] }}"><td>{{ f.id }}</td><td>{{ f.priority }}</td>
<td>{{ f.title }}<br><small>{{ f.rule_id }}</small></td>
<td>{{ f.file }}:{{ f.line }}</td><td>{{ f.ai_explanation }}</td></tr>{% endfor %}
</table>
<p><i>L'IA ne cache jamais une alerte : celles qu'elle conteste restent dans le rapport, avec son avis,
pour qu'un humain tranche. Une faille grave n'est jamais rétrogradée sur son seul avis.</i></p>
{% else %}<p>Aucune.</p>{% endif %}

<h2>Autres alertes (moyennes et basses)</h2>
<table border="1" cellpadding="4" cellspacing="0" width="100%">
<tr bgcolor="#eaecee"><th>ID</th><th>Priorité</th><th>Score</th><th>Alerte</th><th>Paquet / fichier</th><th>Correctif</th></tr>
{% for f in low %}<tr bgcolor="{{ colors[f.priority] }}"><td>{{ f.id }}</td><td>{{ f.priority }}</td><td align="right">{{ f.score }}</td>
<td>{{ f.rule_id }} &middot; {{ f.title[:90] }}</td>
<td>{% if f.file %}{{ f.file }}:{{ f.line }}{% else %}{{ f.packages[:3] | join(', ') }}{% if f.packages | length > 3 %} (+{{ f.packages | length - 3 }}){% endif %}{% endif %}</td>
<td>{{ f.fixed_version or 'aucun' }}</td></tr>{% endfor %}
</table>
{% if low_hidden %}<p><i>+ {{ low_hidden }} autres alertes dans triage.json.</i></p>{% endif %}

<p><small>Généré par le moteur IA TriageX &middot; modèle local {{ s.model }} &middot; EPSS : {{ s.epss_scores }} scores &middot; KEV {{ 'chargé' if s.kev_loaded else 'indisponible' }}</small></p>
</body></html>
"""

_env = Environment(autoescape=True)
_template = _env.from_string(TEMPLATE)


def render_html(result: dict) -> str:
    findings = result["findings"]
    low_all = [f for f in findings if f["priority"] in ("moyenne", "basse")]
    return _template.render(
        build=result.get("build"),
        gate=result["gate"],
        s=result["summary"],
        top=[f for f in findings if f["priority"] in ("critique", "haute")],
        contested=[f for f in findings if f.get("ai_verdict") == "false_positive"],
        low=low_all[:MAX_LOW_ROWS],
        low_hidden=max(len(low_all) - MAX_LOW_ROWS, 0),
        colors=COLORS,
        verdicts=VERDICTS,
    )
