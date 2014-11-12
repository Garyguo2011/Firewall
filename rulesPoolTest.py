# rulesPoolTest.py

from rulesPool import Rule, GeneralRule, DNSRule, StaticRulesPool

staticRulePool = StaticRulesPool("rules.conf")
print(staticRulePool)