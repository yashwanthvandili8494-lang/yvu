import re
import nltk
import numpy as np
from nltk.corpus import wordnet as wn

class ObjectiveTest:

    def __init__(self, filepath, noOfQues):
        # Accept either a path to a file or raw text passed in `filepath`.
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                self.summary = f.read()
        except (FileNotFoundError, OSError, TypeError):
            # If it's not a path, treat the argument as the raw text content.
            self.summary = str(filepath or "")
        self.noOfQues = noOfQues

    def get_trivial_sentences(self):
        try:
            sentences = nltk.sent_tokenize(str(self.summary or ""))
        except Exception:
            sentences = [s.strip() for s in re.split(r"[.!?]+", str(self.summary or "")) if s.strip()]
        trivial_sentences = list()
        for sent in sentences:
            trivial = self.identify_trivial_sentences(sent)
            if trivial:
                trivial_sentences.append(trivial)
            else:
                continue
        return trivial_sentences

    def identify_trivial_sentences(self, sentence):
        if isinstance(sentence, (list, tuple)):
            sentence = " ".join(str(part) for part in sentence)
        sentence = str(sentence or "")

        try:
            tokens = nltk.word_tokenize(sentence)
        except Exception:
            tokens = sentence.split()
        if isinstance(tokens, str):
            tokens = tokens.split() if " " in tokens else [tokens]
        else:
            tokens = [str(token) for token in tokens]

        if not tokens:
            return None

        try:
            tags = nltk.pos_tag(tokens)
        except Exception:
            # Fallback when tagger/tokenizer internals reject input shape.
            tags = [(token, "NN") for token in tokens]

        if not tags or tags[0][1] == "RB" or len(tokens) < 4:
            return None
        
        noun_phrases = [word for word, tag in tags if tag.startswith('NN')]

        replace_nouns = noun_phrases[-1:] if noun_phrases else []
        
        if len(replace_nouns) == 0:
            return None
        
        val = 99
        for i in replace_nouns:
            if len(i) < val:
                val = len(i)
            else:
                continue
        
        trivial = {
            "Answer": " ".join(replace_nouns),
            "Key": val
        }

        if len(replace_nouns) == 1:
            trivial["Similar"] = self.answer_options(replace_nouns[0])
        else:
            trivial["Similar"] = []
        
        replace_phrase = " ".join(replace_nouns)
        blanks_phrase = ("__________" * len(replace_nouns)).strip()
        expression = re.compile(re.escape(replace_phrase), re.IGNORECASE)
        sentence = expression.sub(blanks_phrase, str(sentence), count=1)
        trivial["Question"] = sentence
        return trivial

    @staticmethod
    def answer_options(word):
        synsets = wn.synsets(word, pos="n")

        if len(synsets) == 0:
            return []
        else:
            synset = synsets[0]

        hypernyms = synset.hypernyms()
        if not hypernyms:
            return []
        hypernym = hypernyms[0]
        hyponyms = hypernym.hyponyms()
        similar_words = []
        for hyponym in hyponyms:
            similar_word = hyponym.lemmas()[0].name().replace("_", " ")
            if similar_word != word:
                similar_words.append(similar_word)
            if len(similar_words) == 8:
                break
        return similar_words

    def generate_test(self):
        trivial_pair = self.get_trivial_sentences()
        question_answer = list()
        for que_ans_dict in trivial_pair:
            if que_ans_dict["Key"] > int(self.noOfQues):
                question_answer.append(que_ans_dict)
            else:
                continue
        if not question_answer:
            return [], []
        question = list()
        answer = list()
        while len(question) < int(self.noOfQues):
            rand_num = np.random.randint(0, len(question_answer))
            if question_answer[rand_num]["Question"] not in question:
                question.append(question_answer[rand_num]["Question"])
                answer.append(question_answer[rand_num]["Answer"])
            else:
                continue
        return question, answer
