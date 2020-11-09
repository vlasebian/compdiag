from compdiag.main import Compdiag

from compdiag.diagram.state import State
from compdiag.diagram.transition import Transition
from compdiag.diagram.basediagram import Reconstruct

def reconstruct_modifier(states, transitions):
    # Elimină stările din intervalul dat și tranzițiile asociate
    states, transitions = Reconstruct
        .remove_states(range(13,19), states, transitions)

    # Adaugă 2 tranziții între stările 16, 20 și 15 și 19
    transitions
        .append(Transition('12', '20', None, Reconstruct.ARR_DOWN))
    transitions
        .append(Transition('11', '19', None, Reconstruct.ARR_DOWN))

    # Întoarce noua configurație a diagramei
    return states, transitions

def main():
    Compdiag.rebuild_diagram('dnsdia.json', reconstruct_modifier, 'reconsdiag')


if __name__ == '__main__':
    main()

