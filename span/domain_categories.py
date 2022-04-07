# Copyright 2022 Big Bad Wolf Security, LLC
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of the copyright holder nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from typing import List, Set, Union
from regex import compile
class DomainCategories:
    def __init__(self, policy, custom_domains):
        self.p = policy
        self.uncat_domains = set(str(x) for x in custom_domains)
        self.all_domains = self.uncat_domains
        self.domain_categories = {}
        
    def add(self, cat_name: str, cat: set, strict=True):
        for t in cat:
            self.p.lookup_type(t)
            if strict and t not in self.uncat_domains:
                raise Exception(t + " not in uncat domains")
            
        self.uncat_domains = self.uncat_domains - cat
        self.domain_categories[cat_name] = cat

    def add_from_existing(self, cat_name: str, existing_cats: List[str]):
        new_set = set()
        for existing in existing_cats:
            new_set = new_set.union(getattr(self, existing))

        self.add(cat_name, new_set, strict=False)

    def add_by_prefix(self, cat_name: str, name_prefix: str, strict=True):
        self.add(cat_name, self.get_uncat_by_prefixes(name_prefix), strict=strict)


    def get_uncat_by_prefixes(self, name_prefixes: Union[str, List[str]]) -> Set[str]:
        if isinstance(name_prefixes, str):
            name_prefixes = [name_prefixes]
        def matches_prefixes(x):
            for prefix in name_prefixes:
                if x.startswith(prefix):
                    return True
            return False

        return {x for x in self.uncat_domains if matches_prefixes(x)}

    def add_by_regex(self, cat_name: str, name_regex: str, strict=True):
        self.add(cat_name, self.get_uncat_by_regex(name_regex), strict=strict)

    def add_from_by_regex(self, cat_name: str, name_regex: str, domains: Set[str]):
        """Add from an existing set of domains instead of uncat"""
        self.add(cat_name, self.get_by_regex(name_regex, domains), strict=False)

    def get_uncat_by_regex(self, name_regexes: Union[str, List[str]]) -> Set[str]:
        return self.get_by_regex(name_regexes, self.uncat)

    def get_by_regex(self, name_regexes: Union[str, List[str]], domains: Set[str]) -> Set[str]:
        if isinstance(name_regexes, str):
            name_regexes = [name_regexes]
        matchers = []
        for name_regex in name_regexes:
            matchers.append(compile(name_regex))
        
        def matches_prefixes(x):
            for matcher in matchers:
                if matcher.match(x) is not None:
                    return True
            return False

        return {x for x in domains if matches_prefixes(x)}

        
    def get(self, cat_name: str):
        return self.domain_categories[cat_name]
    
    @property
    def uncat(self):
        return self.uncat_domains
    
    def __getattr__(self, name):
        if name in self.domain_categories:
            return self.domain_categories[name]
        
        raise AttributeError(name)