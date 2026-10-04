"""DOM XSS monitor script builders and payload list (mixin)."""

from __future__ import annotations

from typing import List, Dict, Optional, Any

from bugtrace.utils.logger import get_logger

logger = get_logger("tools.dom_xss")


class DOMXSSScriptsMixin:
    """Builds injected monitor JS and default DOM XSS payloads."""

    def _get_monitor_script(self) -> str:
        """
        TASK-55: Enhanced taint tracking for DOM XSS detection.
        Monitors dangerous sinks AND tracks tainted sources.

        IMPROVED (2026-01-30): Added AngularJS-specific monitoring.
        """
        parts = [
            self._build_monitor_header(),
            self._build_source_tracking(),
            self._build_sink_monitoring(),
            self._build_jquery_hooks(),
            self._build_angular_hooks(),
            self._build_event_listener_tracking(),
            "console.log('DOMXSS_MONITOR_INJECTED_V4');"
        ]
        return f"(function() {{ {' '.join(parts)} }})();"

    def _build_monitor_header(self) -> str:
        """Initialize monitoring arrays and canary constant."""
        return """
            window.__domxss_findings = [];
            window.__domxss_sources = [];
            const CANARY = 'BUGTRACEAI_7x7';
        """

    def _build_source_tracking(self) -> str:
        """Build source tracking hooks for location.hash, .search, and document.referrer."""
        return """
            const originalHashDesc = Object.getOwnPropertyDescriptor(Location.prototype, 'hash');
            if (originalHashDesc && originalHashDesc.get) {
                Object.defineProperty(Location.prototype, 'hash', {
                    get: function() {
                        const value = originalHashDesc.get.call(this);
                        if (value && value.includes(CANARY)) {
                            window.__domxss_sources.push({source: 'location.hash', value: value});
                        }
                        return value;
                    },
                    set: originalHashDesc.set
                });
            }
            const originalSearchDesc = Object.getOwnPropertyDescriptor(Location.prototype, 'search');
            if (originalSearchDesc && originalSearchDesc.get) {
                Object.defineProperty(Location.prototype, 'search', {
                    get: function() {
                        const value = originalSearchDesc.get.call(this);
                        if (value && value.includes(CANARY)) {
                            window.__domxss_sources.push({source: 'location.search', value: value});
                        }
                        return value;
                    },
                    set: originalSearchDesc.set
                });
            }
            const originalReferrer = Object.getOwnPropertyDescriptor(Document.prototype, 'referrer');
            if (originalReferrer && originalReferrer.get) {
                Object.defineProperty(Document.prototype, 'referrer', {
                    get: function() {
                        const value = originalReferrer.get.call(this);
                        if (value && value.includes(CANARY)) {
                            window.__domxss_sources.push({source: 'document.referrer', value: value});
                        }
                        return value;
                    }
                });
            }
        """

    def _build_sink_monitoring(self) -> str:
        """Build sink monitoring hooks for innerHTML, eval, document.write, etc."""
        return """
            const originalInnerHTMLDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
            if (originalInnerHTMLDesc) {
                Object.defineProperty(Element.prototype, 'innerHTML', {
                    set: function(value) {
                        if (value && value.toString().includes(CANARY)) {
                            window.__domxss_findings.push({
                                sink: 'innerHTML',
                                value: value.toString().substring(0, 500),
                                element: this.tagName,
                                sources: [...window.__domxss_sources]
                            });
                            console.error('DOMXSS_DETECTED:innerHTML:' + value.toString().substring(0, 200));
                        }
                        return originalInnerHTMLDesc.set.call(this, value);
                    },
                    get: originalInnerHTMLDesc.get
                });
            }
            const originalOuterHTMLDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
            if (originalOuterHTMLDesc && originalOuterHTMLDesc.set) {
                Object.defineProperty(Element.prototype, 'outerHTML', {
                    set: function(value) {
                        if (value && value.toString().includes(CANARY)) {
                            window.__domxss_findings.push({
                                sink: 'outerHTML',
                                value: value.toString().substring(0, 500),
                                element: this.tagName,
                                sources: [...window.__domxss_sources]
                            });
                            console.error('DOMXSS_DETECTED:outerHTML:' + value.toString().substring(0, 200));
                        }
                        return originalOuterHTMLDesc.set.call(this, value);
                    },
                    get: originalOuterHTMLDesc.get
                });
            }
            const originalWrite = document.write;
            document.write = function(content) {
                if (content && content.toString().includes(CANARY)) {
                    window.__domxss_findings.push({
                        sink: 'document.write',
                        value: content.toString().substring(0, 500),
                        sources: [...window.__domxss_sources]
                    });
                    console.error('DOMXSS_DETECTED:document.write:' + content.toString().substring(0, 200));
                }
                return originalWrite.apply(this, arguments);
            };
            const originalWriteln = document.writeln;
            document.writeln = function(content) {
                if (content && content.toString().includes(CANARY)) {
                    window.__domxss_findings.push({
                        sink: 'document.writeln',
                        value: content.toString().substring(0, 500),
                        sources: [...window.__domxss_sources]
                    });
                    console.error('DOMXSS_DETECTED:document.writeln:' + content.toString().substring(0, 200));
                }
                return originalWriteln.apply(this, arguments);
            };
            const originalEval = window.eval;
            window.eval = function(code) {
                if (code && code.toString().includes(CANARY)) {
                    window.__domxss_findings.push({
                        sink: 'eval',
                        value: code.toString().substring(0, 500),
                        sources: [...window.__domxss_sources]
                    });
                    console.error('DOMXSS_DETECTED:eval:' + code.toString().substring(0, 200));
                }
                return originalEval.apply(this, arguments);
            };
            const OriginalFunction = window.Function;
            window.Function = function(...args) {
                const code = args.join(',');
                if (code.includes(CANARY)) {
                    window.__domxss_findings.push({
                        sink: 'Function',
                        value: code.substring(0, 500),
                        sources: [...window.__domxss_sources]
                    });
                    console.error('DOMXSS_DETECTED:Function:' + code.substring(0, 200));
                }
                return new OriginalFunction(...args);
            };
            const originalSetTimeout = window.setTimeout;
            window.setTimeout = function(handler, timeout, ...args) {
                if (typeof handler === 'string' && handler.includes(CANARY)) {
                    window.__domxss_findings.push({
                        sink: 'setTimeout',
                        value: handler.substring(0, 500),
                        sources: [...window.__domxss_sources]
                    });
                    console.error('DOMXSS_DETECTED:setTimeout:' + handler.substring(0, 200));
                }
                return originalSetTimeout.apply(this, arguments);
            };
            const originalSetInterval = window.setInterval;
            window.setInterval = function(handler, timeout, ...args) {
                if (typeof handler === 'string' && handler.includes(CANARY)) {
                    window.__domxss_findings.push({
                        sink: 'setInterval',
                        value: handler.substring(0, 500),
                        sources: [...window.__domxss_sources]
                    });
                    console.error('DOMXSS_DETECTED:setInterval:' + handler.substring(0, 200));
                }
                return originalSetInterval.apply(this, arguments);
            };
            // Hook setAttribute to detect href/src/action set to executable URIs
            const originalSetAttribute = Element.prototype.setAttribute;
            Element.prototype.setAttribute = function(name, value) {
                if (value && typeof value === 'string') {
                    const lv = value.toLowerCase().trim();
                    const nm = name.toLowerCase();
                    if (nm === 'href' || nm === 'src' || nm === 'action' || nm === 'formaction') {
                        // Flag ONLY javascript:/data: URIs that carry OUR canary. Without the canary
                        // check the page's OWN javascript: links (ASP.NET __doPostBack, javascript:void(0))
                        // fire this hook → false-positive DOM XSS on every param tested.
                        if ((lv.startsWith('javascript:') || lv.startsWith('data:')) && value.includes(CANARY)) {
                            window.__domxss_findings.push({
                                sink: 'setAttribute.' + name,
                                value: value.substring(0, 500),
                                element: this.tagName,
                                sources: [...window.__domxss_sources]
                            });
                            console.error('DOMXSS_DETECTED:setAttribute.' + name + ':' + value.substring(0, 200));
                        }
                    } else if (nm === 'onclick' || nm === 'onerror' || nm === 'onload') {
                        // Event handler attributes: canary in value = XSS
                        if (value.includes(CANARY)) {
                            window.__domxss_findings.push({
                                sink: 'setAttribute.' + name,
                                value: value.substring(0, 500),
                                element: this.tagName,
                                sources: [...window.__domxss_sources]
                            });
                        }
                    }
                }
                return originalSetAttribute.apply(this, arguments);
            };
            // Hook HTMLAnchorElement.href property setter
            // jQuery .attr('href', value) uses elem.href = value (property access),
            // NOT setAttribute(). This catches both jQuery and vanilla JS property assignment.
            const hrefDesc = Object.getOwnPropertyDescriptor(HTMLAnchorElement.prototype, 'href');
            if (hrefDesc && hrefDesc.set) {
                Object.defineProperty(HTMLAnchorElement.prototype, 'href', {
                    set: function(value) {
                        if (value && typeof value === 'string') {
                            const lv = value.toLowerCase().trim();
                            // Flag ONLY javascript:/data: URIs that carry OUR canary — the page's own
                            // javascript: hrefs (ASP.NET __doPostBack, javascript:void(0)) are NOT our XSS.
                            if ((lv.startsWith('javascript:') || lv.startsWith('data:')) && value.includes(CANARY)) {
                                window.__domxss_findings.push({
                                    sink: 'a.href',
                                    value: value.substring(0, 500),
                                    element: 'A',
                                    sources: [...window.__domxss_sources]
                                });
                                console.error('DOMXSS_DETECTED:a.href:' + value.substring(0, 200));
                            }
                        }
                        return hrefDesc.set.call(this, value);
                    },
                    get: hrefDesc.get
                });
            }
        """

    def _build_jquery_hooks(self) -> str:
        """Build jQuery-specific hooks if jQuery is present."""
        return """
            if (window.jQuery) {
                const CANARY = 'BUGTRACEAI_7x7';
                const originalHtml = jQuery.fn.html;
                jQuery.fn.html = function(value) {
                    if (value && value.toString().includes(CANARY)) {
                        window.__domxss_findings.push({
                            sink: 'jQuery.html',
                            value: value.toString().substring(0, 500),
                            sources: [...window.__domxss_sources]
                        });
                        console.error('DOMXSS_DETECTED:jQuery.html:' + value.toString().substring(0, 200));
                    }
                    return originalHtml.apply(this, arguments);
                };
                const originalAppend = jQuery.fn.append;
                jQuery.fn.append = function(value) {
                    if (value && value.toString().includes(CANARY)) {
                        window.__domxss_findings.push({
                            sink: 'jQuery.append',
                            value: value.toString().substring(0, 500),
                            sources: [...window.__domxss_sources]
                        });
                        console.error('DOMXSS_DETECTED:jQuery.append:' + value.toString().substring(0, 200));
                    }
                    return originalAppend.apply(this, arguments);
                };
                // Hook jQuery.attr() to detect href/src/action sinks
                const originalAttr = jQuery.fn.attr;
                jQuery.fn.attr = function(name, value) {
                    if (arguments.length > 1 && value && typeof value === 'string') {
                        const dangerousAttrs = ['href', 'src', 'action', 'data', 'formaction'];
                        if (dangerousAttrs.includes(name.toLowerCase())) {
                            const lv = value.toLowerCase().trim();
                            // Flag ONLY javascript:/data: URIs that carry OUR canary (skip the page's own javascript: links)
                            if ((lv.startsWith('javascript:') || lv.startsWith('data:')) && value.includes(CANARY)) {
                                window.__domxss_findings.push({
                                    sink: 'jQuery.attr.' + name,
                                    value: value.substring(0, 500),
                                    element: this[0] ? this[0].tagName : 'unknown',
                                    sources: [...window.__domxss_sources]
                                });
                                console.error('DOMXSS_DETECTED:jQuery.attr.' + name + ':' + value.substring(0, 200));
                            }
                        }
                    }
                    return originalAttr.apply(this, arguments);
                };
            }
        """

    def _build_angular_hooks(self) -> str:
        """ADDED (2026-01-30): Build AngularJS-specific hooks for template execution detection."""
        return """
            if (window.angular) {
                const CANARY = 'BUGTRACEAI_7x7';
                // Monitor Angular template compilation
                const originalCompile = angular.element.prototype.html;
                if (originalCompile) {
                    angular.element.prototype.html = function(value) {
                        if (value && value.toString().includes(CANARY)) {
                            window.__domxss_findings.push({
                                sink: 'angular.element.html',
                                value: value.toString().substring(0, 500),
                                sources: [...window.__domxss_sources]
                            });
                            console.error('DOMXSS_DETECTED:angular.element.html:' + value.toString().substring(0, 200));
                        }
                        return originalCompile.apply(this, arguments);
                    };
                }
                // Monitor $compile service if available
                try {
                    const injector = angular.element(document).injector();
                    if (injector) {
                        const originalCompileService = injector.get('$compile');
                        if (originalCompileService) {
                            injector.get('$rootScope').$watch(function() {
                                const template = document.body.innerHTML;
                                if (template.includes(CANARY) && template.includes('{{')) {
                                    window.__domxss_findings.push({
                                        sink: '$compile',
                                        value: 'AngularJS template evaluation with user input',
                                        sources: [...window.__domxss_sources]
                                    });
                                    console.error('DOMXSS_DETECTED:$compile:AngularJS');
                                }
                            });
                        }
                    }
                } catch (e) {
                    // Injector not ready yet
                }
            }
        """

    def _build_event_listener_tracking(self) -> str:
        """Hook addEventListener to mark elements with JS-attached event handlers.

        Modern apps use addEventListener instead of inline onclick attributes.
        This hook marks those elements with a data attribute so we can click them
        later to trigger DOM XSS via onclick/onmouseover/onfocus handlers.
        """
        return """
            const origAddEventListener = EventTarget.prototype.addEventListener;
            EventTarget.prototype.addEventListener = function(type, handler, options) {
                const interactiveEvents = ['click', 'mouseover', 'mouseenter', 'focus', 'touchstart'];
                if (interactiveEvents.includes(type) && this.setAttribute) {
                    try {
                        const existing = this.getAttribute('data-domxss-handler') || '';
                        if (!existing.includes(type)) {
                            this.setAttribute('data-domxss-handler', existing ? existing + ',' + type : type);
                        }
                    } catch(e) {}
                }
                return origAddEventListener.apply(this, arguments);
            };
        """

    def _get_dom_xss_payloads(self) -> List[Dict[str, str]]:
        """
        Returns payloads designed for DOM XSS detection.
        Each payload contains a canary that our hooks will detect.

        IMPROVED (2026-01-30): Added AngularJS-specific payloads for ginandjuice.shop.
        """
        canary = "BUGTRACEAI_7x7"

        return [
            {"payload": canary, "type": "canary"},
            # javascript: protocol payloads FIRST — critical for location.href DOM XSS sinks
            {"payload": f"javascript:alert('{canary}')", "type": "javascript_uri"},
            {"payload": f"javascript:alert(document.domain)//", "type": "javascript_domain"},
            {"payload": f"<img src=x onerror=alert('{canary}')>", "type": "img_onerror"},
            {"payload": f"<svg onload=alert('{canary}')>", "type": "svg_onload"},
            {"payload": f"'-alert('{canary}')-'", "type": "js_breakout_single"},
            {"payload": f'"-alert("{canary}")-"', "type": "js_breakout_double"},
            # Attribute injection for document.write sinks (breaks out of src/value attribute)
            # Works when < is blocked (WAF) but " passes through
            {"payload": f'" onload="alert(\'{canary}\')', "type": "attr_injection_onload"},
            {"payload": f'" onfocus="alert(\'{canary}\')" autofocus="', "type": "attr_injection_onfocus"},
            {"payload": f"</script><script>alert('{canary}')</script>", "type": "script_breakout"},
            # ADDED (2026-01-30): AngularJS-specific payloads
            {"payload": f"{{{{constructor.constructor('alert(\"{canary}\")')()}}}}", "type": "angular_constructor"},
            {"payload": f"{{{{$on.constructor('alert(\"{canary}\")')()}}}}", "type": "angular_on"},
            {"payload": f"{{{{['a]'constructor.prototype.charAt=[].join;$eval('x={canary}');'x'}}}}", "type": "angular_sandbox_bypass"},
            # ADDED (2026-02-12): Vue.js template injection payloads
            {"payload": f"{{{{_openBlock.constructor('alert(\"{canary}\")')()}}}}", "type": "vue_constructor"},
            {"payload": f"{{{{this.constructor.constructor('alert(\"{canary}\")')()}}}}", "type": "vue_this_constructor"},
            # ADDED (2026-02-12): React dangerouslySetInnerHTML context
            {"payload": f"<div dangerouslySetInnerHTML={{{{__html: '<img src=x onerror=alert(\"{canary}\")>'}}}}></div>", "type": "react_dangerously"},
        ]


