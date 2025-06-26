import logging
from rapticoressvc.epss_helper import categorize_epss_score


def generate_risk_language(ssvc_result, epss_data=None):
    """
    Generate descriptive risk language explaining the SSVC decision
    
    Args:
        ssvc_result (dict): SSVC analysis result containing all vectors and recommendation
        epss_data (dict): EPSS score data for the vulnerability
    
    Returns:
        dict: Contains detailed risk explanation and summary
    """
    try:
        # Extract key information
        recommendation = ssvc_result.get('ssvc_rec', 'review')
        exploitation = ssvc_result.get('Exploitation', 'none')
        exposure = ssvc_result.get('Exposure', 'unlikely')
        utility = ssvc_result.get('Utility', 'laborious')
        impact = ssvc_result.get('Impact', 'low')
        cvss_score = ssvc_result.get('vulnerability_score')
        asset_type = ssvc_result.get('asset_type', 'unknown')
        environment = ssvc_result.get('environment', 'unknown')
        public_status = ssvc_result.get('public_status', 'unknown')
        asset_criticality = ssvc_result.get('asset_criticality', 'unknown')
        
        # Get EPSS information
        epss_score = None
        epss_percentile = None
        epss_category = "unknown"
        
        if epss_data:
            epss_score = epss_data.get('epss_score')
            epss_percentile = epss_data.get('percentile')
            epss_category = categorize_epss_score(epss_score)
        
        # Generate risk summary
        risk_summary = _generate_risk_summary(recommendation, epss_category)
        
        # Generate detailed explanation
        detailed_explanation = _generate_detailed_explanation(
            recommendation, exploitation, exposure, utility, impact,
            cvss_score, epss_score, epss_percentile, epss_category,
            asset_type, environment, public_status, asset_criticality
        )
        
        # Generate action items
        action_items = _generate_action_items(recommendation, epss_category)
        
        # Generate risk factors breakdown
        risk_factors = _generate_risk_factors_breakdown(
            exploitation, exposure, utility, impact, epss_category
        )
        
        return {
            'risk_summary': risk_summary,
            'detailed_explanation': detailed_explanation,
            'action_items': action_items,
            'risk_factors': risk_factors,
            'epss_score': epss_score,
            'epss_percentile': epss_percentile,
            'epss_category': epss_category
        }
        
    except Exception as e:
        logging.exception(f"Error generating risk language: {e}")
        return {
            'risk_summary': "Unable to generate risk assessment due to an error.",
            'detailed_explanation': "Risk assessment generation failed.",
            'action_items': ["Review the vulnerability manually"],
            'risk_factors': {},
            'epss_score': None,
            'epss_percentile': None,
            'epss_category': "unknown"
        }


def _generate_risk_summary(recommendation, epss_category):
    """Generate a concise risk summary"""
    summaries = {
        'act_now': {
            'very_high': "CRITICAL RISK: This vulnerability requires immediate attention. It has a very high likelihood of being exploited and poses severe risk to your system.",
            'high': "HIGH RISK: This vulnerability requires immediate attention. It has a high likelihood of being exploited and poses significant risk to your system.",
            'medium': "HIGH RISK: This vulnerability requires immediate attention despite moderate exploit likelihood due to its critical nature.",
            'low': "HIGH RISK: This vulnerability requires immediate attention due to its critical nature, even though exploit likelihood is low.",
            'very_low': "HIGH RISK: This vulnerability requires immediate attention due to its critical nature, even though exploit likelihood is very low.",
            'unknown': "HIGH RISK: This vulnerability requires immediate attention due to its critical nature."
        },
        'out-of-cycle': {
            'very_high': "ELEVATED RISK: This vulnerability should be patched ahead of schedule due to high exploit likelihood.",
            'high': "ELEVATED RISK: This vulnerability should be patched ahead of schedule due to elevated exploit likelihood.",
            'medium': "ELEVATED RISK: This vulnerability should be patched ahead of schedule.",
            'low': "ELEVATED RISK: This vulnerability should be patched ahead of schedule despite low exploit likelihood.",
            'very_low': "ELEVATED RISK: This vulnerability should be patched ahead of schedule despite very low exploit likelihood.",
            'unknown': "ELEVATED RISK: This vulnerability should be patched ahead of schedule."
        },
        'schedule': {
            'very_high': "MODERATE RISK: This vulnerability should be patched according to regular schedule despite high exploit likelihood.",
            'high': "MODERATE RISK: This vulnerability should be patched according to regular schedule.",
            'medium': "MODERATE RISK: This vulnerability should be patched according to regular schedule.",
            'low': "LOW RISK: This vulnerability can be patched according to regular schedule.",
            'very_low': "LOW RISK: This vulnerability can be patched according to regular schedule.",
            'unknown': "MODERATE RISK: This vulnerability should be patched according to regular schedule."
        },
        'defer': {
            'very_high': "LOW RISK: This vulnerability can be deferred despite high exploit likelihood due to low business impact.",
            'high': "LOW RISK: This vulnerability can be deferred despite elevated exploit likelihood due to low business impact.",
            'medium': "LOW RISK: This vulnerability can be deferred due to low business impact.",
            'low': "LOW RISK: This vulnerability can be safely deferred.",
            'very_low': "LOW RISK: This vulnerability can be safely deferred.",
            'unknown': "LOW RISK: This vulnerability can be deferred due to low business impact."
        },
        'review': {
            'very_high': "REVIEW REQUIRED: This vulnerability needs manual review due to high exploit likelihood but insufficient data for automated assessment.",
            'high': "REVIEW REQUIRED: This vulnerability needs manual review due to elevated exploit likelihood but insufficient data for automated assessment.",
            'medium': "REVIEW REQUIRED: This vulnerability needs manual review due to insufficient data for automated assessment.",
            'low': "REVIEW REQUIRED: This vulnerability needs manual review due to insufficient data for automated assessment.",
            'very_low': "REVIEW REQUIRED: This vulnerability needs manual review due to insufficient data for automated assessment.",
            'unknown': "REVIEW REQUIRED: This vulnerability needs manual review due to insufficient data for automated assessment."
        }
    }
    
    return summaries.get(recommendation, {}).get(epss_category, "Risk assessment unavailable.")


def _generate_detailed_explanation(recommendation, exploitation, exposure, utility, impact,
                                 cvss_score, epss_score, epss_percentile, epss_category,
                                 asset_type, environment, public_status, asset_criticality):
    """Generate detailed explanation of the risk assessment"""
    
    explanation_parts = []
    
    # Recommendation explanation
    recommendation_explanations = {
        'act_now': "This vulnerability requires immediate patching due to the combination of high exploitability and significant business impact.",
        'out-of-cycle': "This vulnerability should be patched ahead of the regular schedule due to elevated risk factors.",
        'schedule': "This vulnerability should be patched according to the regular patching schedule.",
        'defer': "This vulnerability can be deferred due to low business impact despite potential exploitability.",
        'review': "This vulnerability requires manual review due to insufficient data for automated assessment."
    }
    
    explanation_parts.append(recommendation_explanations.get(recommendation, "Assessment recommendation unavailable."))
    
    # Exploitation status
    if exploitation == 'active':
        explanation_parts.append("⚠️ ACTIVE EXPLOITATION: This vulnerability is currently being actively exploited in the wild.")
    elif exploitation == 'PoC':
        explanation_parts.append("🔍 PROOF OF CONCEPT: Public proof-of-concept exploits are available for this vulnerability.")
    elif exploitation == 'none':
        explanation_parts.append("📋 NO KNOWN EXPLOITS: No public exploits or active exploitation has been observed.")
    
    # EPSS information
    if epss_score is not None:
        epss_percentile_text = f" (top {100 - (epss_percentile * 100):.1f}% of vulnerabilities)" if epss_percentile else ""
        explanation_parts.append(f"🎯 EXPLOIT PREDICTION: EPSS score of {epss_score:.3f}{epss_percentile_text} indicates {epss_category.replace('_', ' ')} exploit likelihood.")
    
    # CVSS information
    if cvss_score:
        explanation_parts.append(f"📊 CVSS SCORE: {cvss_score} - {_get_cvss_severity(cvss_score)} severity.")
    
    # Asset context
    asset_context = f"🏢 ASSET CONTEXT: {asset_type} asset in {environment} environment"
    if public_status != 'unknown':
        asset_context += f" ({public_status} access)"
    if asset_criticality != 'unknown':
        asset_context += f" with {asset_criticality} business criticality"
    explanation_parts.append(asset_context + ".")
    
    # Risk factors summary
    risk_factors = []
    if exposure == 'unavoidable':
        risk_factors.append("high exposure likelihood")
    elif exposure == 'probable':
        risk_factors.append("moderate exposure likelihood")
    
    if utility == 'effortless':
        risk_factors.append("easy exploitation")
    elif utility == 'complex':
        risk_factors.append("moderate exploitation complexity")
    
    if impact == 'very high':
        risk_factors.append("very high business impact")
    elif impact == 'high':
        risk_factors.append("high business impact")
    
    if risk_factors:
        explanation_parts.append(f"⚖️ RISK FACTORS: {', '.join(risk_factors)}.")
    
    return " ".join(explanation_parts)


def _generate_action_items(recommendation, epss_category):
    """Generate specific action items based on recommendation and EPSS category"""
    
    base_actions = {
        'act_now': [
            "Immediately apply available patches or mitigations",
            "Implement additional monitoring and alerting",
            "Consider temporary workarounds if patches are not immediately available",
            "Notify relevant stakeholders of the critical risk",
            "Review and update incident response procedures"
        ],
        'out-of-cycle': [
            "Schedule patching ahead of regular maintenance windows",
            "Implement additional monitoring",
            "Prepare rollback plans for the patch",
            "Notify stakeholders of the elevated risk"
        ],
        'schedule': [
            "Include in next regular patching cycle",
            "Monitor for any changes in exploit availability",
            "Document the vulnerability for tracking"
        ],
        'defer': [
            "Monitor for changes in exploit availability",
            "Reassess if business context changes",
            "Document for future review"
        ],
        'review': [
            "Conduct manual security assessment",
            "Gather additional vulnerability information",
            "Consult with security team for expert opinion",
            "Monitor for new exploit information"
        ]
    }
    
    actions = base_actions.get(recommendation, ["Review the vulnerability manually"])
    
    # Add EPSS-specific actions
    if epss_category in ['very_high', 'high']:
        actions.append("Monitor EPSS scores for changes in exploit likelihood")
        if recommendation not in ['act_now', 'out-of-cycle']:
            actions.append("Consider upgrading priority if EPSS score increases")
    
    return actions


def _generate_risk_factors_breakdown(exploitation, exposure, utility, impact, epss_category):
    """Generate breakdown of individual risk factors"""
    
    return {
        'exploitation': {
            'value': exploitation,
            'description': _get_exploitation_description(exploitation),
            'risk_level': _get_exploitation_risk_level(exploitation)
        },
        'exposure': {
            'value': exposure,
            'description': _get_exposure_description(exposure),
            'risk_level': _get_exposure_risk_level(exposure)
        },
        'utility': {
            'value': utility,
            'description': _get_utility_description(utility),
            'risk_level': _get_utility_risk_level(utility)
        },
        'impact': {
            'value': impact,
            'description': _get_impact_description(impact),
            'risk_level': _get_impact_risk_level(impact)
        },
        'epss': {
            'value': epss_category,
            'description': _get_epss_description(epss_category),
            'risk_level': _get_epss_risk_level(epss_category)
        }
    }


def _get_cvss_severity(score):
    """Get CVSS severity level"""
    if isinstance(score, str):
        return score
    elif score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    else:
        return "Low"


def _get_exploitation_description(exploitation):
    descriptions = {
        'active': 'Currently being exploited in the wild',
        'PoC': 'Public proof-of-concept exploits available',
        'none': 'No known public exploits'
    }
    return descriptions.get(exploitation, 'Unknown exploitation status')


def _get_exploitation_risk_level(exploitation):
    levels = {
        'active': 'high',
        'PoC': 'medium',
        'none': 'low'
    }
    return levels.get(exploitation, 'unknown')


def _get_exposure_description(exposure):
    descriptions = {
        'unavoidable': 'Very likely to be successfully exploited',
        'probable': 'Moderately likely to be successfully exploited',
        'unlikely': 'Unlikely to be successfully exploited'
    }
    return descriptions.get(exposure, 'Unknown exposure likelihood')


def _get_exposure_risk_level(exposure):
    levels = {
        'unavoidable': 'high',
        'probable': 'medium',
        'unlikely': 'low'
    }
    return levels.get(exposure, 'unknown')


def _get_utility_description(utility):
    descriptions = {
        'effortless': 'Very easy to exploit with minimal effort',
        'complex': 'Moderate effort required to exploit',
        'laborious': 'Significant effort required to exploit'
    }
    return descriptions.get(utility, 'Unknown exploitation complexity')


def _get_utility_risk_level(utility):
    levels = {
        'effortless': 'high',
        'complex': 'medium',
        'laborious': 'low'
    }
    return levels.get(utility, 'unknown')


def _get_impact_description(impact):
    descriptions = {
        'very high': 'Critical business impact if exploited',
        'high': 'Significant business impact if exploited',
        'medium': 'Moderate business impact if exploited',
        'low': 'Minimal business impact if exploited'
    }
    return descriptions.get(impact, 'Unknown business impact')


def _get_impact_risk_level(impact):
    levels = {
        'very high': 'high',
        'high': 'high',
        'medium': 'medium',
        'low': 'low'
    }
    return levels.get(impact, 'unknown')


def _get_epss_description(epss_category):
    descriptions = {
        'very_high': 'Very high likelihood of exploitation within 30 days',
        'high': 'High likelihood of exploitation within 30 days',
        'medium': 'Moderate likelihood of exploitation within 30 days',
        'low': 'Low likelihood of exploitation within 30 days',
        'very_low': 'Very low likelihood of exploitation within 30 days',
        'unknown': 'Unknown exploitation likelihood'
    }
    return descriptions.get(epss_category, 'Unknown exploitation likelihood')


def _get_epss_risk_level(epss_category):
    levels = {
        'very_high': 'high',
        'high': 'high',
        'medium': 'medium',
        'low': 'low',
        'very_low': 'low',
        'unknown': 'unknown'
    }
    return levels.get(epss_category, 'unknown') 