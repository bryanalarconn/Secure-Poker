import secrets

# card values go from 1 to 15
CARD_MIN = 1
CARD_MAX = 15

# each player gets 3 cards
HAND_SIZE = 3

# best 2 out of 3 rounds wins
NUM_ROUNDS = 3
ROUNDS_TO_WIN = 2

# possible round results
P1_WIN = "player1"
P2_WIN = "player2"
TIE = "tie"
DRAW = "draw"

# replaces random.sample(), too predictable and unfit for cryptographic use
_secure_rng = secrets.SystemRandom()

def deal_hand():
    return _secure_rng.sample(range(CARD_MIN, CARD_MAX + 1), HAND_SIZE)


def validate_choice(choice, hand):
    # checks if the card is actually in the hand
    return choice in hand


def compare_round(p1_choice, p2_choice):
    # higher card wins
    if p1_choice > p2_choice:
        return P1_WIN
    if p2_choice > p1_choice:
        return P2_WIN
    return TIE


def determine_winner(round_results):
    # count how many rounds each player won
    p1_wins = round_results.count(P1_WIN)
    p2_wins = round_results.count(P2_WIN)

    # whoever wins 2 rounds wins the game
    if p1_wins >= ROUNDS_TO_WIN:
        return P1_WIN
    if p2_wins >= ROUNDS_TO_WIN:
        return P2_WIN

    # no overall winner
    return DRAW

if __name__ == "__main__":
    p1_hand = deal_hand()
    p2_hand = deal_hand()

    print("player 1 hand:", p1_hand)
    print("player 2 hand:", p2_hand)

    round_results = []

    for i in range(NUM_ROUNDS):
        p1_choice = p1_hand[i]
        p2_choice = p2_hand[i]

        result = compare_round(p1_choice, p2_choice)
        round_results.append(result)

        print("round", i + 1)
        print("player 1 played:", p1_choice)
        print("player 2 played:", p2_choice)
        print("result:", result)
        print()

    winner = determine_winner(round_results)
    print("overall winner:", winner)