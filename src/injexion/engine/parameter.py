"""
Universal parameter discovery, parsing, and payload mutation engine.
Replaces legacy string concatenation with RFC-compliant parameter injection.
"""

import copy
from typing import Any, Dict, List, Optional
import urllib.parse

from injexion.core.models import InjectionTarget, ParameterType


class ParameterParser:
    """Parses targets and generates structured injection candidates."""

    @staticmethod
    def extract_targets_from_url(url: str, method: str = "GET") -> List[InjectionTarget]:
        """Extract all injectable parameters from a URL's query string."""
        targets: List[InjectionTarget] = []
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            # If no parameters exist, treat path tail as potential injection point
            targets.append(
                InjectionTarget(
                    url=url,
                    method=method,
                    parameter="__path__",
                    param_type=ParameterType.PATH,
                    baseline_value=parsed.path,
                )
            )
            return targets

        # Strip query string from base URL for clean target definition
        base_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))

        for param_name, values in params.items():
            baseline_val = values[0] if values else ""
            targets.append(
                InjectionTarget(
                    url=base_url,
                    method=method,
                    parameter=param_name,
                    param_type=ParameterType.QUERY,
                    baseline_value=baseline_val,
                )
            )

        return targets

    @staticmethod
    def build_mutated_request(
        target: InjectionTarget,
        payload: str,
        original_url: str,
        mode: str = "replace",  # "replace" or "append"
    ) -> Dict[str, Any]:
        """Generate parameters or body with payload injected into the target."""
        parsed = urllib.parse.urlparse(original_url)
        query_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        if target.param_type == ParameterType.QUERY:
            new_params = copy.deepcopy(query_params)
            base_val = target.baseline_value
            injected_val = (base_val + payload) if mode == "append" else payload
            new_params[target.parameter] = [injected_val]

            # Flatten parse_qs lists back into single values or list
            flattened = {k: v[0] if len(v) == 1 else v for k, v in new_params.items()}
            base_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
            return {
                "method": target.method,
                "url": base_url,
                "params": flattened,
                "data": None,
                "json_body": None,
                "headers": None,
            }

        elif target.param_type == ParameterType.PATH:
            # Inject directly into URL path
            new_path = parsed.path.rstrip("/") + "/" + urllib.parse.quote(payload)
            mutated_url = urllib.parse.urlunparse(
                (parsed.scheme, parsed.netloc, new_path, parsed.params, parsed.query, parsed.fragment)
            )
            return {
                "method": target.method,
                "url": mutated_url,
                "params": None,
                "data": None,
                "json_body": None,
                "headers": None,
            }

        elif target.param_type == ParameterType.HEADER:
            headers = copy.deepcopy(target.headers)
            headers[target.parameter] = payload
            return {
                "method": target.method,
                "url": original_url,
                "params": None,
                "data": None,
                "json_body": None,
                "headers": headers,
            }

        elif target.param_type == ParameterType.JSON and target.json_data:
            json_body = copy.deepcopy(target.json_data)
            json_body[target.parameter] = payload
            return {
                "method": target.method,
                "url": original_url,
                "params": None,
                "data": None,
                "json_body": json_body,
                "headers": None,
            }

        elif target.param_type == ParameterType.FORM and target.form_data:
            form_data = copy.deepcopy(target.form_data)
            form_data[target.parameter] = payload
            return {
                "method": target.method,
                "url": original_url,
                "params": None,
                "data": form_data,
                "json_body": None,
                "headers": None,
            }

        # Fallback
        return {
            "method": target.method,
            "url": original_url,
            "params": {target.parameter: payload},
            "data": None,
            "json_body": None,
            "headers": None,
        }

