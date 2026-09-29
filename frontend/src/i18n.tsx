/**
 * Bilingual strings (English / Devanagari).
 *
 * The backend emits `title` and `title_hi` on every finding, so finding text
 * needs no lookup. This dictionary covers only the chrome the API does not
 * provide: navigation, posture dimensions, severities, and the fixed UI labels.
 *
 * Kannada was present in the reference application. It was dropped here rather
 * than machine-translated, because a legal-evidence tool should not ship
 * unverified translations. Add a `kn` block once reviewed strings exist.
 */

import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'

export type Lang = 'en' | 'hi'

export const LANGS: Lang[] = ['en', 'hi']
export const LANG_NAMES: Record<Lang, string> = { en: 'English', hi: 'हिन्दी' }

const en: Record<string, string> = {
  // navigation
  'KryxAI': 'KryxAI',
  'Overview': 'Overview',
  'New scan': 'New scan',
  'Findings': 'Findings',
  'Captures': 'Captures',
  'Evidence chain': 'Evidence chain',
  'Capabilities': 'Capabilities',

  // passive framing — must appear wherever the tool is described
  'Passive mail-security forensics': 'Passive mail-security forensics',
  'Observes an existing capture. It never probes, scans or modifies anything.':
    'Observes an existing capture. It never probes, scans or modifies anything.',
  'This is not a compliance determination.': 'This is not a compliance determination.',
  'A clean report is not proof of a compliant control; it reflects only the traffic present in the supplied capture.':
    'A clean report is not proof of a compliant control; it reflects only the traffic present in the supplied capture.',

  // scan
  'Choose a capture': 'Choose a capture',
  'Drop a .pcap or .pcapng file here, or choose one from disk':
    'Drop a .pcap or .pcapng file here, or choose one from disk',
  'Analyse capture': 'Analyse capture',
  'Analysing...': 'Analysing...',
  'Scan a file already on the server': 'Scan a file already on the server',
  'Server-side path': 'Server-side path',
  'No capture analysed yet': 'No capture analysed yet',
  'Upload a capture to see posture, findings and the evidence chain.':
    'Upload a capture to see posture, findings and the evidence chain.',

  // posture
  'Posture': 'Posture',
  'Security posture': 'Security posture',
  'Not assessed': 'Not assessed',
  'Sessions measured': 'Sessions measured',
  'Scoring dimensions': 'Scoring dimensions',

  // dimensions
  'transport_encryption': 'Transport encryption',
  'tamper_resistance': 'Tamper resistance',
  'certificate_hygiene': 'Certificate hygiene',
  'forward_secrecy': 'Forward secrecy',
  'evidence_integrity': 'Evidence integrity',

  // severities
  'sev.critical': 'Critical',
  'sev.high': 'High',
  'sev.medium': 'Medium',
  'sev.low': 'Low',
  'sev.info': 'Informational',

  // chain states — these are the words that must never be softened
  'chain.pending': 'Pending external anchor',
  'chain.anchored': 'Anchored',
  'chain.demo': 'Demo',
  'Not anchored': 'Not anchored',
  'Anchor required and not met': 'Anchor required and not met',
  'Chain valid': 'Chain valid',
  'Chain broken': 'Chain broken',
  'Block': 'Block',
  'Difficulty': 'Difficulty',
  'Provider': 'Provider',
  'Transaction': 'Transaction',

  // sessions
  'STARTTLS': 'STARTTLS',
  'TLS': 'TLS',
  'Version': 'Version',
  'Cipher': 'Cipher',
  'Group': 'Group',
  'Certificate': 'Certificate',
  'SNI': 'SNI',
  'Endpoint': 'Endpoint',
  'Protocol': 'Protocol',
  'Bytes': 'Bytes',
  'Reassembly': 'Reassembly',
  'Complete': 'Complete',
  'Incomplete': 'Incomplete',
  'no TLS': 'no TLS',
  'suppressed': 'suppressed',
  'refused': 'refused',
  'upgraded': 'upgraded',
  'not offered': 'not offered',
  'Obfuscated': 'Obfuscated',
  'A visibility limit, not a passing result.': 'A visibility limit, not a passing result.',
  'No dimensions could be scored from this capture.':
    'No dimensions could be scored from this capture.',
  'No further detail available.': 'No further detail available.',

  // findings
  'Remediation': 'Remediation',
  'Confidence': 'Confidence',
  'Detection weight': 'Detection weight',
  'Ordering heuristic, not a probability': 'Ordering heuristic, not a probability',
  'Reference': 'Reference',
  'Evidence': 'Evidence',
  'Risk breakdown': 'Risk breakdown',
  'Why this finding': 'Why this finding',
  'No findings': 'No findings',
  'No findings in this capture.': 'No findings in this capture.',
  '{n} finding(s)': '{n} finding(s)',

  // requirement coverage
  'Requirement coverage': 'Requirement coverage',
  'Derived from this scan’s own output rather than asserted. A clean row means the requirement was evaluated across the sessions and nothing adverse was found, which is the desired outcome. An empty circle means this particular capture contains nothing that exercises it.':
    'Derived from this scan’s own output rather than asserted. A clean row means the requirement was evaluated across the sessions and nothing adverse was found, which is the desired outcome. An empty circle means this particular capture contains nothing that exercises it.',
  evidenced: 'evidenced',
  'checked, clean': 'checked, clean',
  'not in this capture': 'not in this capture',
  'Hide evidence': 'Hide evidence',
  '{n} evidence': '{n} evidence',
  'Show fewer': 'Show fewer',
  'Show all {n} requirements': 'Show all {n} requirements',

  // downgrade / interception
  'Downgrade & interception evidence': 'Downgrade & interception evidence',
  'Assessed': 'Assessed',
  'Advertisement altered': 'Advertisement altered',
  'Upgraded': 'Upgraded',
  'Cleartext': 'Cleartext',
  'Expected': 'Expected',
  'observed in the greeting': 'observed in the greeting',
  'Why a live scanner cannot make this claim': 'Why a live scanner cannot make this claim',
  'Confidence in the structural signature, not a probability':
    'Confidence in the structural signature, not a probability',
  state: 'state',
  encrypted: 'encrypted',
  confidence: 'confidence',
  anomaly: 'anomaly',
  'The upgrade was offered and completed. The greeting matched the token this protocol defines, and every byte after the handshake was encrypted.':
    'The upgrade was offered and completed. The greeting matched the token this protocol defines, and every byte after the handshake was encrypted.',
  'This session stayed in cleartext, but the advertisement matched the token this protocol defines. That is an unconfigured listener, not a rewritten greeting.':
    'This session stayed in cleartext, but the advertisement matched the token this protocol defines. That is an unconfigured listener, not a rewritten greeting.',

  // limits
  'Limitations': 'Limitations',
  'Known limitations': 'Known limitations',
  'What this build cannot see': 'What this build cannot see',

  // model scoring clamp
  'Model scoring clamp': 'Model scoring clamp',
  '{n} session(s) had inputs outside the range the model was trained on and were clamped before scoring.':
    '{n} session(s) had inputs outside the range the model was trained on and were clamped before scoring.',
  'Constant in training:': 'Constant in training:',

  // DPDP statutory mapping
  'DPDP statutory mapping': 'DPDP statutory mapping',
  'observation(s) mapped': 'observation(s) mapped',
  'Statutory text:': 'Statutory text:',
  'No finding in this capture mapped to a DPDP provision.':
    'No finding in this capture mapped to a DPDP provision.',
  'Detail': 'Detail',
  'Hide detail': 'Hide detail',
  'Exposure:': 'Exposure:',
  'Relevance:': 'Relevance:',

  // errors
  'Dismiss': 'Dismiss',
  'Retry': 'Retry',
  'Error: {e}': 'Error: {e}',
  'Failed to load report': 'Failed to load report',
  'Report not in memory': 'Report not in memory',
}

const hi: Record<string, string> = {
  'KryxAI': 'क्रिक्सएआई',
  'Overview': 'अवलोकन',
  'New scan': 'नया स्कैन',
  'Findings': 'निष्कर्ष',
  'Captures': 'कैप्चर',
  'Evidence chain': 'साक्ष्य शृंखला',
  'Capabilities': 'क्षमताएँ',

  'Passive mail-security forensics': 'निष्क्रिय ई-मेल सुरक्षा फोरेंसिक्स',
  'Observes an existing capture. It never probes, scans or modifies anything.':
    'यह केवल मौजूदा कैप्चर का अवलोकन करता है। यह कभी कुछ जाँच, स्कैन या परिवर्तन नहीं करता।',
  'This is not a compliance determination.': 'यह अनुपालन का निर्णय नहीं है।',
  'A clean report is not proof of a compliant control; it reflects only the traffic present in the supplied capture.':
    'स्वच्छ रिपोर्ट अनुपालनकारी नियंत्रण का प्रमाण नहीं है; यह केवल दिए गए कैप्चर में मौजूद ट्रैफ़िक का प्रतिबिंब है।',

  'Choose a capture': 'कैप्चर चुनें',
  'Drop a .pcap or .pcapng file here, or choose one from disk':
    'यहाँ .pcap या .pcapng फ़ाइल छोड़ें, या डिस्क से चुनें',
  'Analyse capture': 'कैप्चर का विश्लेषण करें',
  'Analysing...': 'विश्लेषण हो रहा है...',
  'Scan a file already on the server': 'सर्वर पर मौजूद फ़ाइल स्कैन करें',
  'Server-side path': 'सर्वर-साइड पथ',
  'No capture analysed yet': 'अभी तक कोई कैप्चर विश्लेषित नहीं हुआ',
  'Upload a capture to see posture, findings and the evidence chain.':
    'स्थिति, निष्कर्ष और साक्ष्य शृंखला देखने के लिए कैप्चर अपलोड करें।',

  'Posture': 'स्थिति',
  'Security posture': 'सुरक्षा स्थिति',
  'Not assessed': 'मूल्यांकन नहीं हुआ',
  'Sessions measured': 'मापे गए सत्र',
  'Scoring dimensions': 'स्कोरिंग आयाम',

  'transport_encryption': 'परिवहन एन्क्रिप्शन',
  'tamper_resistance': 'छेड़छाइट प्रतिरोध',
  'certificate_hygiene': 'प्रमाणपत्र स्वच्छता',
  'forward_secrecy': 'फ़ॉरवर्ड सीक्रेसी',
  'evidence_integrity': 'साक्ष्य अखंडता',

  'sev.critical': 'गंभीर',
  'sev.high': 'उच्च',
  'sev.medium': 'मध्यम',
  'sev.low': 'निम्न',
  'sev.info': 'सूचनात्मक',

  'chain.pending': 'बाहरी एंकर लंबित',
  'chain.anchored': 'एंकर किया गया',
  'chain.demo': 'डेमो',
  'Not anchored': 'एंकर नहीं किया गया',
  'Anchor required and not met': 'एंकर आवश्यक था, पूरा नहीं हुआ',
  'Chain valid': 'शृंखला वैध',
  'Chain broken': 'शृंखला टूटी',
  'Block': 'ब्लॉक',
  'Difficulty': 'कठिनाई',
  'Provider': 'प्रदाता',
  'Transaction': 'लेन-देन',

  'STARTTLS': 'STARTTLS',
  'TLS': 'TLS',
  'Version': 'संस्करण',
  'Cipher': 'साइफ़र',
  'Group': 'समूह',
  'Certificate': 'प्रमाणपत्र',
  'SNI': 'SNI',
  'Endpoint': 'एंडपॉइंट',
  'Protocol': 'प्रोटोकॉल',
  'Bytes': 'बाइट',
  'Reassembly': 'पुनर्निर्माण',
  'Complete': 'पूर्ण',
  'Incomplete': 'अपूर्ण',
  'no TLS': 'कोई TLS नहीं',
  'suppressed': 'दबाया गया',
  'refused': 'अस्वीकृत',
  'upgraded': 'उन्नत',
  'not offered': 'प्रस्तावित नहीं',
  'Obfuscated': 'तिरोधित',
  'A visibility limit, not a passing result.': 'यह दृश्यता की सीमा है, उत्तीर्ण परिणाम नहीं।',
  'No dimensions could be scored from this capture.':
    'इस कैप्चर से किसी आयाम का स्कोर नहीं निकाला जा सका।',
  'No further detail available.': 'और विवरण उपलब्ध नहीं है।',

  'Remediation': 'उपचार',
  'Confidence': 'विश्वास',
  'Detection weight': 'पहचान भार',
  'Ordering heuristic, not a probability': 'यह क्रमब्ध सूक्ष्मनीति है, संभावना नहीं।',
  'Reference': 'संदर्भ',
  'Evidence': 'साक्ष्य',
  'Risk breakdown': 'जोखिम विवरण',
  'Why this finding': 'यह निष्कर्ष क्यों',
  'No findings': 'कोई निष्कर्ष नहीं',
  'No findings in this capture.': 'इस कैप्चर में कोई निष्कर्ष नहीं है।',
  '{n} finding(s)': '{n} निष्कर्ष',

  'Requirement coverage': 'आवश्यकताओं की पूर्ति',
  'Derived from this scan’s own output rather than asserted. A clean row means the requirement was evaluated across the sessions and nothing adverse was found, which is the desired outcome. An empty circle means this particular capture contains nothing that exercises it.':
    'यह इस स्कैन के अपने आउटपुट से प्राप्त किया गया है, केवल दावा नहीं। साफ़ पंक्ति का अर्थ है कि आवश्यकता सत्रों में मूल्यांकित की गई और कोई प्रतिकूल बात नहीं मिली, जो अपेक्षित परिणाम है। खाली वृत्त का अर्थ है कि इस विशेष कैप्चर में ऐसा कुछ नहीं है।',
  evidenced: 'प्रमाणित',
  'checked, clean': 'जाँचा गया, साफ़',
  'not in this capture': 'इस कैप्चर में नहीं',
  'Hide evidence': 'प्रमाण छिपाएँ',
  '{n} evidence': '{n} प्रमाण',
  'Show fewer': 'कम दिखाएँ',
  'Show all {n} requirements': 'सभी {n} आवश्यकताएँ दिखाएँ',

  'Downgrade & interception evidence': 'डाउनग्रेड और अंतरायन (इंटरसेप्शन) प्रमाण',
  'Assessed': 'मूल्यांकित',
  'Advertisement altered': 'विज्ञापन बदला गया',
  'Upgraded': 'उन्नत (अपग्रेड) हुआ',
  'Cleartext': 'सादा पाठ',
  'Expected': 'अपेक्षित',
  'observed in the greeting': 'स्वागत संदेश में देखा गया',
  'Why a live scanner cannot make this claim':
    'लाइव स्कैनर यह दावा क्यों नहीं कर सकता',
  'Confidence in the structural signature, not a probability':
    'संरचनात्मक हस्ताक्षर में विश्वास, संभावना नहीं',
  state: 'स्थिति',
  encrypted: 'एन्क्रिप्टेड',
  confidence: 'विश्वास',
  anomaly: 'विषमता',
  'The upgrade was offered and completed. The greeting matched the token this protocol defines, and every byte after the handshake was encrypted.':
    'अपग्रेड की पेशकश की गई और पूरी हुई। स्वागत संदेश इस प्रोटोकॉल द्वारा परिभाषित टोकन से मेल खाता था, और हैंडशेक के बाद का प्रत्येक बाइट एन्क्रिप्टेड था।',
  'This session stayed in cleartext, but the advertisement matched the token this protocol defines. That is an unconfigured listener, not a rewritten greeting.':
    'यह सत्र सादे पाठ में ही रहा, लेकिन विज्ञापन इस प्रोटोकॉल द्वारा परिभाषित टोकन से मेल खाता था। यह अव्यवस्थित श्रोता है, पुनर्लिखित स्वागत संदेश नहीं।',

  'Limitations': 'सीमाएँ',
  'Known limitations': 'ज्ञात सीमाएँ',
  'What this build cannot see': 'यह संस्करण क्या नहीं देख सकता',

  // model scoring clamp
  'Model scoring clamp': 'मॉडल स्कोरिंग क्लैम्प',
  '{n} session(s) had inputs outside the range the model was trained on and were clamped before scoring.':
    '{n} सत्रों के इनपुट प्रशिक्षण सीमा से बाहर थे, अतः स्कोरिंग से पहले उन्हें सीमित (क्लैम्प) किया गया।',
  'Constant in training:': 'प्रशिक्षण में स्थिर:',

  // DPDP statutory mapping
  'DPDP statutory mapping': 'DPDP वैधानिक मानचित्रण',
  'observation(s) mapped': 'अवलोकन मैप किए गए',
  'Statutory text:': 'वैधानिक पाठ:',
  'No finding in this capture mapped to a DPDP provision.':
    'इस कैप्चर में कोई निष्कर्ष DPDP प्रावधान से मैप नहीं हुआ।',
  'Detail': 'विवरण',
  'Hide detail': 'विवरण छिपाएँ',
  'Exposure:': 'जोखिम:',
  'Relevance:': 'प्रासंगिकता:',

  'Dismiss': 'बंद करें',
  'Retry': 'पुनः प्रयास',
  'Error: {e}': 'त्रुटि: {e}',
  'Failed to load report': 'रिपोर्ट लोड नहीं हो सकी',
  'Report not in memory': 'रिपोर्ट मेमोरी में नहीं है',
}

const dict: Record<Lang, Record<string, string>> = { en, hi }

type T = (key: string, vars?: Record<string, string | number>) => string

type Ctx = {
  lang: Lang
  setLang: (l: Lang) => void
  t: T
}

const I18nContext = createContext<Ctx>({ lang: 'en', setLang: () => {}, t: (k) => k })

export function LanguageProvider({ children }: { children: ReactNode }) {
  const [lang, setLang] = useState<Lang>(() => {
    const stored = localStorage.getItem('kryxai-lang')
    return stored === 'hi' ? 'hi' : 'en'
  })

  useEffect(() => {
    localStorage.setItem('kryxai-lang', lang)
    document.documentElement.lang = lang
  }, [lang])

  const t: T = (key, vars) => {
    let s = dict[lang][key] ?? dict.en[key] ?? key
    if (vars) {
      for (const [k, v] of Object.entries(vars)) s = s.split(`{${k}}`).join(String(v))
    }
    return s
  }

  return <I18nContext.Provider value={{ lang, setLang, t }}>{children}</I18nContext.Provider>
}

// eslint-disable-next-line react-refresh/only-export-components
export function useI18n() {
  return useContext(I18nContext)
}

// eslint-disable-next-line react-refresh/only-export-components
export function useT(): T {
  return useContext(I18nContext).t
}

/**
 * Pick the localised field of a backend-supplied object.
 *
 * The API ships `title` and `title_hi` on every finding. `translation_complete`
 * tells us whether the Devanagari text is a reviewed translation, so a partial
 * translation falls back to English rather than showing half a sentence.
 */
export function localized<T extends { title: string; title_hi?: string; translation_complete?: boolean }>(
  obj: T,
  lang: Lang,
): string {
  if (lang === 'hi' && obj.title_hi && obj.translation_complete !== false) return obj.title_hi
  return obj.title
}
