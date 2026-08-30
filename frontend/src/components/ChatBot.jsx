/* src/components/ChatBot.jsx
   NIRIKSHAK-AI :: Groq AI Security Chatbot with Voice
   Powered by Groq llama-3.3-70b & Web Speech API */
import React, { useState, useRef, useEffect } from 'react';
import axios from 'axios';
import {
  MessageCircle, X, Send, Bot, User, Loader2,
  ShieldAlert, Phone, Mic, MicOff, Volume2, VolumeX,
} from 'lucide-react';

const API_BASE = 'http://localhost:8001';

const QUICK_PROMPTS = [
  '🚨 What should I do immediately after finding this malware?',
  '🔒 How do I protect my bank account now?',
  '📞 How do I report this to Cyber Cell India?',
  '📱 Should I factory reset my phone?',
];

const SYSTEM_MSG = `You are NIRIKSHAK CyberGuard, an elite AI security assistant for NIRIKSHAK-AI, an advanced mobile malware analysis platform used by Indian banks, CERT-In, and cybersecurity teams.

Your role:
1. Guide users who have discovered a malicious APK with immediate incident response protocols.
2. Provide clear, actionable, and highly professional cybersecurity advice in simple language. You can respond in Hindi or English.
3. Explain the forensic analysis, what the malware may have done (like intercepting SMS or tracking location), and the associated risks.
4. Urgently guide them to report to Cyber Cell India (visit cybercrime.gov.in, call helpline 1930).
5. Give step-by-step emergency precautions to secure bank accounts, UPI, and personal data.

Always be calm, reassuring, and precise. Use simple language. Give numbered steps when giving instructions. Keep responses concise but highly informative (under 150 words). Do NOT provide legal advice.`;

export default function ChatBot({ masterData }) {
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);

  // ── Voice state ───────────────────────────────────────────────────────────
  const [isListening, setIsListening] = useState(false);
  const [isSpeaking, setIsSpeaking] = useState(false);
  const [voiceEnabled, setVoiceEnabled] = useState(true);
  const [micPermission, setMicPermission] = useState('unknown'); // 'granted'|'denied'|'prompt'|'unknown'

  const messagesEndRef = useRef(null);
  const recognitionRef = useRef(null);

  // ── 1. Check mic permission on mount (so icon can show warning early) ─────
  useEffect(() => {
    if (navigator.permissions) {
      navigator.permissions
        .query({ name: 'microphone' })
        .then((result) => {
          setMicPermission(result.state);
          result.onchange = () => setMicPermission(result.state);
        })
        .catch(() => setMicPermission('unknown'));
    }
  }, []);

  // ── 2. Create and configure SpeechRecognition instance ───────────────────
  useEffect(() => {
    const SpeechRecognition =
      window.SpeechRecognition || window.webkitSpeechRecognition;

    if (!SpeechRecognition) {
      console.warn('Web Speech API not available. Use Google Chrome.');
      return;
    }

    const recognition = new SpeechRecognition();

    // FIX A: 'en-IN' causes recognition to fail silently on Chrome/Windows.
    //        'en-US' is fully supported and understands Indian-accented English.
    recognition.lang = 'en-US';

    // FIX B: continuous=true prevents the recognizer from stopping itself
    //        after a short pause between words.
    recognition.continuous = true;
    recognition.interimResults = true;

    recognition.onresult = (event) => {
      let interim = '';
      let final = '';
      for (let i = event.resultIndex; i < event.results.length; i++) {
        if (event.results[i].isFinal) {
          final += event.results[i][0].transcript;
        } else {
          interim += event.results[i][0].transcript;
        }
      }
      // Show interim text in the input box while user is speaking
      if (interim) setInput(interim);
      if (final) {
        setInput(final);
        recognition.stop();
        setIsListening(false);
        // FIX C: Use a custom event to avoid stale closure on sendMessage
        window.dispatchEvent(
          new CustomEvent('nirikshak_speech_final', { detail: final })
        );
      }
    };

    recognition.onerror = (event) => {
      setIsListening(false);
      const msgs = {
        'not-allowed':
          '🎤 Microphone access denied. Click the 🔒 icon in your browser address bar → set Microphone to **Allow** → refresh the page.',
        'no-speech':
          '🔇 No speech detected. Please speak clearly closer to your microphone.',
        'network':
          '🌐 Network error. Chrome\'s speech recognition requires an internet connection.',
        'audio-capture':
          '🎤 No microphone found. Please connect a microphone and try again.',
        'aborted': null, // user manually stopped — no toast needed
      };
      const msg = msgs[event.error];
      if (msg) {
        setMessages((prev) => [
          ...prev,
          { role: 'assistant', content: `⚠️ **Voice Error:** ${msg}` },
        ]);
      }
      console.error('Speech recognition error:', event.error);
    };

    recognition.onend = () => setIsListening(false);

    recognitionRef.current = recognition;

    return () => {
      recognition.abort();
      window.speechSynthesis.cancel();
    };
  }, []);

  // ── 3. Listen for speech_final event (avoids stale closures) ─────────────
  useEffect(() => {
    const handler = (e) => {
      const text = e.detail;
      if (text) sendMessage(text);
    };
    window.addEventListener('nirikshak_speech_final', handler);
    return () => window.removeEventListener('nirikshak_speech_final', handler);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [masterData]);

  // ── 4. Toggle mic with explicit permission request ────────────────────────
  const toggleListening = async () => {
    if (isListening) {
      recognitionRef.current?.stop();
      setIsListening(false);
      return;
    }

    // Explicitly request mic access — shows the native browser permission prompt
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      // Immediately stop the stream (we only needed the permission grant)
      stream.getTracks().forEach((t) => t.stop());
      setMicPermission('granted');
    } catch {
      setMicPermission('denied');
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content:
            '⚠️ **Microphone blocked!** Click the 🔒 lock icon in your browser address bar → set **Microphone** to **Allow** → refresh the page and try again.',
        },
      ]);
      return;
    }

    setInput('');
    window.speechSynthesis.cancel();
    try {
      recognitionRef.current?.start();
      setIsListening(true);
    } catch (err) {
      // recognition.start() throws if already started
      console.warn('Could not start recognition:', err.message);
    }
  };

  // ── 5. Text-to-speech ─────────────────────────────────────────────────────
  const speakText = (text) => {
    if (!voiceEnabled || !('speechSynthesis' in window)) return;
    window.speechSynthesis.cancel();
    const clean = text
      .replace(/[*#_`]/g, '')
      .replace(/[\u{1F600}-\u{1F6FF}]/gu, '');
    const utterance = new SpeechSynthesisUtterance(clean);
    // FIX D: 'hi-IN' sometimes has no voice installed on Windows.
    //        Fall back to 'en-IN' then 'en-US'.
    const voices = window.speechSynthesis.getVoices();
    const preferred =
      voices.find((v) => v.lang === 'en-IN') ||
      voices.find((v) => v.lang === 'hi-IN') ||
      voices.find((v) => v.lang.startsWith('en'));
    if (preferred) utterance.voice = preferred;
    utterance.lang = preferred?.lang || 'en-US';
    utterance.rate = 1.05;
    utterance.pitch = 1.1;
    utterance.onstart = () => setIsSpeaking(true);
    utterance.onend = () => setIsSpeaking(false);
    utterance.onerror = () => setIsSpeaking(false);
    window.speechSynthesis.speak(utterance);
  };

  // ── Auto-scroll ───────────────────────────────────────────────────────────
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // ── Welcome message on analysis completion ────────────────────────────────
  useEffect(() => {
    if (masterData) {
      const welcome = `🛡️ I've analyzed the threat report. A **${
        masterData?.risk_assessment?.severity_tier || 'HIGH'
      }** risk APK (*${
        masterData?.app_metadata?.file_name || 'unknown'
      }*) has been detected with a threat score of **${
        masterData?.risk_assessment?.final_score || 0
      }/100**. How can I help you stay safe?`;
      setMessages([{ role: 'assistant', content: welcome }]);
      speakText('I have analyzed the threat report. How can I help you stay safe?');
    } else {
      setMessages([
        {
          role: 'assistant',
          content:
            "🛡️ Hello! I'm NIRIKSHAK CyberGuard. Upload an APK first, then I can guide you on what to do next.",
        },
      ]);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [masterData]);

  // ── Send message ──────────────────────────────────────────────────────────
  const sendMessage = async (text) => {
    const userText = (text || input).trim();
    if (!userText || loading) return;

    setInput('');
    setIsListening(false);
    recognitionRef.current?.stop();
    window.speechSynthesis.cancel();

    setMessages((prev) => {
      const next = [...prev, { role: 'user', content: userText }];
      fireApiCall(next, userText);
      return next;
    });
  };

  const fireApiCall = async (currentMessages, userText) => {
    setLoading(true);
    let context = '';
    if (masterData) {
      const ra = masterData.risk_assessment || {};
      const sa = masterData.static_analysis || {};
      context =
        `\n\nCurrent Analysis Context:\n` +
        `- File: ${masterData.app_metadata?.file_name}\n` +
        `- Threat Score: ${ra.final_score}/100 (${ra.severity_tier})\n` +
        `- Dangerous Permissions: ${(sa.dangerous_permissions || []).join(', ')}\n` +
        `- Primary Exploit: ${masterData.genai_forensics?.primary_exploit || 'UNKNOWN'}`;
    }

    try {
      const res = await axios.post(
        `${API_BASE}/api/v1/chat`,
        {
          messages: currentMessages.map((m) => ({
            role: m.role,
            content: m.content,
          })),
          system: SYSTEM_MSG + context,
        },
        { timeout: 30000 }
      );
      const reply =
        res.data?.reply ||
        res.data?.message ||
        'Sorry, I could not get a response.';
      setMessages((prev) => [...prev, { role: 'assistant', content: reply }]);
      speakText(reply);
    } catch {
      const fallback =
        '⚠️ I am unable to reach the AI server right now. For immediate help, please call 1930.';
      setMessages((prev) => [...prev, { role: 'assistant', content: fallback }]);
      speakText(fallback);
    } finally {
      setLoading(false);
    }
  };

  // ── Mic button icon + colour based on permission state ───────────────────
  const micTitle =
    micPermission === 'denied'
      ? 'Microphone blocked — click for fix'
      : isListening
      ? 'Stop Listening'
      : 'Speak (Hindi / English)';

  return (
    <>
      {/* Floating Button */}
      <button
        onClick={() => {
          setOpen((v) => !v);
          if (open) window.speechSynthesis.cancel();
        }}
        className={`fixed bottom-6 right-6 z-50 w-14 h-14 rounded-full shadow-2xl flex items-center justify-center transition-all duration-300 ${
          open
            ? 'bg-slate-700 border border-slate-600 scale-90'
            : 'bg-gradient-to-r from-cyan-500 to-blue-500 hover:scale-105 hover:shadow-cyan-500/50'
        }`}
        title="CyberGuard AI Assistant"
      >
        {open ? (
          <X size={22} className="text-slate-200" />
        ) : (
          <MessageCircle size={22} className="text-white" />
        )}
        {!open && (
          <span className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-red-500 border-2 border-slate-950 animate-pulse" />
        )}
      </button>

      {/* Chat Panel */}
      {open && (
        <div className="fixed bottom-24 right-6 z-50 w-[380px] max-h-[600px] flex flex-col rounded-2xl border border-cyan-500/30 bg-slate-950/95 backdrop-blur-xl shadow-2xl shadow-cyan-500/10 overflow-hidden transform transition-all duration-300 origin-bottom-right">
          {/* Header */}
          <div className="flex items-center gap-3 p-4 border-b border-slate-700/50 bg-gradient-to-r from-cyan-950 to-slate-900 relative overflow-hidden">
            <div className="absolute inset-0 bg-[url('https://www.transparenttextures.com/patterns/cubes.png')] opacity-10 mix-blend-overlay" />

            <div className="relative z-10 w-10 h-10 rounded-full bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center shadow-lg shadow-cyan-500/20">
              <ShieldAlert size={20} className="text-cyan-400" />
            </div>

            <div className="relative z-10 flex-1">
              <div className="text-sm font-black text-slate-100 flex items-center gap-2">
                NIRIKSHAK CyberGuard
                {isSpeaking && (
                  <span className="flex gap-0.5 items-end h-3">
                    <span className="w-0.5 h-full bg-cyan-400 animate-pulse" />
                    <span className="w-0.5 h-2/3 bg-cyan-400 animate-pulse" style={{ animationDelay: '0.1s' }} />
                    <span className="w-0.5 h-4/5 bg-cyan-400 animate-pulse" style={{ animationDelay: '0.2s' }} />
                  </span>
                )}
              </div>
              <div className="text-[10px] text-cyan-400/80 mono flex items-center gap-1 font-semibold mt-0.5">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse inline-block" />
                Voice-Enabled Groq AI
              </div>
            </div>

            <button
              onClick={() => { setVoiceEnabled(!voiceEnabled); window.speechSynthesis.cancel(); }}
              className="relative z-10 p-2 rounded-full bg-white/5 hover:bg-white/10 transition-colors text-slate-300"
              title={voiceEnabled ? 'Mute Voice Responses' : 'Enable Voice Responses'}
            >
              {voiceEnabled ? <Volume2 size={16} /> : <VolumeX size={16} className="text-slate-500" />}
            </button>
          </div>

          {/* Messages */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4 min-h-0 max-h-[380px] bg-slate-900/50">
            {messages.map((msg, i) => (
              <div key={i} className={`flex gap-3 ${msg.role === 'user' ? 'flex-row-reverse' : ''}`}>
                <div className={`w-7 h-7 rounded-full flex-shrink-0 flex items-center justify-center mt-1 shadow-md ${
                  msg.role === 'user'
                    ? 'bg-gradient-to-br from-blue-500 to-cyan-500'
                    : 'bg-slate-800 border border-slate-700'
                }`}>
                  {msg.role === 'user' ? (
                    <User size={14} className="text-white" />
                  ) : (
                    <Bot size={14} className="text-cyan-400" />
                  )}
                </div>
                <div className={`max-w-[80%] px-4 py-2.5 rounded-2xl text-xs leading-relaxed shadow-sm ${
                  msg.role === 'user'
                    ? 'bg-gradient-to-br from-cyan-600 to-blue-600 text-white rounded-tr-sm'
                    : 'bg-slate-800 border border-slate-700/50 text-slate-200 rounded-tl-sm'
                }`}>
                  {msg.content.split('\n').map((line, li) => (
                    <p key={li} className={li > 0 ? 'mt-1.5' : ''}>
                      {line.split(/(\*\*.*?\*\*)/).map((part, idx) =>
                        part.startsWith('**') && part.endsWith('**') ? (
                          <strong key={idx} className={msg.role === 'user' ? 'text-white' : 'text-cyan-300 font-bold'}>
                            {part.slice(2, -2)}
                          </strong>
                        ) : part
                      )}
                    </p>
                  ))}
                </div>
              </div>
            ))}

            {loading && (
              <div className="flex gap-3">
                <div className="w-7 h-7 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center flex-shrink-0">
                  <Bot size={14} className="text-cyan-400" />
                </div>
                <div className="px-4 py-2.5 rounded-2xl rounded-tl-sm bg-slate-800 border border-slate-700/50 flex items-center gap-2">
                  <Loader2 size={14} className="text-cyan-400 animate-spin" />
                  <span className="text-xs text-slate-400 font-medium">Analyzing threat context...</span>
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* Quick Prompts */}
          {messages.length <= 2 && (
            <div className="px-4 pb-3 flex flex-wrap gap-2 bg-slate-900/50">
              {QUICK_PROMPTS.slice(0, 3).map((p, i) => (
                <button
                  key={i}
                  onClick={() => sendMessage(p)}
                  className="text-[10px] px-2.5 py-1.5 rounded-lg bg-slate-800 border border-slate-700 text-slate-300 hover:text-white hover:border-cyan-500/50 hover:bg-slate-700 transition-all text-left shadow-sm font-medium"
                >
                  {p}
                </button>
              ))}
            </div>
          )}

          {/* Input Area */}
          <div className="p-3 border-t border-slate-700/80 bg-slate-900 relative">
            {isListening && (
              <div className="absolute -top-8 left-0 right-0 flex justify-center animate-bounce">
                <span className="bg-red-500/20 border border-red-500/30 text-red-400 px-3 py-1 rounded-full text-[10px] font-bold flex items-center gap-2 backdrop-blur-md">
                  <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
                  Listening — Speak now...
                </span>
              </div>
            )}
            {micPermission === 'denied' && !isListening && (
              <div className="absolute -top-7 left-0 right-0 flex justify-center">
                <span className="bg-orange-500/20 border border-orange-500/30 text-orange-400 px-3 py-1 rounded-full text-[10px] font-bold">
                  🎤 Mic blocked — click mic icon for fix
                </span>
              </div>
            )}

            <div className="flex gap-2 items-center bg-slate-950 p-1.5 rounded-xl border border-slate-700 focus-within:border-cyan-500/50 transition-colors shadow-inner">
              <button
                onClick={toggleListening}
                className={`w-9 h-9 rounded-lg flex items-center justify-center transition-all flex-shrink-0 ${
                  isListening
                    ? 'bg-red-500/20 text-red-400 shadow-[0_0_15px_rgba(239,68,68,0.3)] animate-pulse'
                    : micPermission === 'denied'
                    ? 'bg-orange-900/30 text-orange-400'
                    : 'bg-slate-800 text-slate-400 hover:text-cyan-400 hover:bg-slate-700'
                }`}
                title={micTitle}
              >
                {isListening ? <MicOff size={16} /> : <Mic size={16} />}
              </button>

              <input
                type="text"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && !e.shiftKey && sendMessage()}
                placeholder={isListening ? 'Listening...' : 'Type or speak to CyberGuard...'}
                className="flex-1 bg-transparent text-xs text-slate-200 placeholder-slate-500 outline-none px-1"
              />

              <button
                onClick={() => sendMessage()}
                disabled={!input.trim() || loading}
                className="w-9 h-9 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 disabled:from-slate-800 disabled:to-slate-800 disabled:text-slate-500 text-white flex items-center justify-center hover:from-cyan-500 hover:to-blue-500 transition-all flex-shrink-0 shadow-md"
              >
                <Send size={14} className={input.trim() && !loading ? 'translate-x-0.5' : ''} />
              </button>
            </div>

            <div className="flex justify-between items-center mt-2 px-1">
              <a href="tel:1930" className="flex items-center gap-1.5 text-[9px] text-red-400 font-bold hover:text-red-300">
                <Phone size={10} /> 1930 Helpline
              </a>
              <span className="text-[9px] text-slate-500 font-medium">Secured by Groq AI</span>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
