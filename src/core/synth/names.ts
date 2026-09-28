// Name pools for synthetic people. Common given/family names, combined at
// random — nobody real is being portrayed.

export const FIRST_NAMES: readonly string[] = [
  'Anna', 'Ben', 'Carla', 'David', 'Elena', 'Felix', 'Greta', 'Hannah', 'Ivan', 'Julia',
  'Karim', 'Lena', 'Marco', 'Nina', 'Oskar', 'Paula', 'Quentin', 'Rosa', 'Samir', 'Tara',
  'Umar', 'Vera', 'Wei', 'Xenia', 'Yusuf', 'Zoe', 'Aisha', 'Bruno', 'Chloe', 'Dario',
  'Emma', 'Farah', 'Georg', 'Helena', 'Ilse', 'Jonas', 'Kofi', 'Lucia', 'Mateo', 'Noor',
  'Olga', 'Pieter', 'Rahul', 'Sofia', 'Tomas', 'Ursula', 'Viktor', 'Wanda', 'Yara', 'Zeynep',
  'Arjun', 'Bea', 'Cyril', 'Dana', 'Erik', 'Fatima', 'Gabriel', 'Hugo', 'Ines', 'Jana',
  'Kai', 'Leo', 'Mia', 'Nils', 'Omar', 'Priya', 'Ruth', 'Stefan', 'Theo', 'Yuki',
];

export const LAST_NAMES: readonly string[] = [
  'Albrecht', 'Bauer', 'Costa', 'Dubois', 'Engel', 'Fischer', 'Garcia', 'Hartmann', 'Ivanova', 'Jansen',
  'Kaya', 'Lindqvist', 'Moreau', 'Novak', 'Okafor', 'Petrov', 'Quinn', 'Rossi', 'Schmidt', 'Tanaka',
  'Ueda', 'Vogel', 'Weber', 'Yilmaz', 'Zimmermann', 'Andersen', 'Becker', 'Chen', 'Demir', 'Evans',
  'Ferreira', 'Graf', 'Horvat', 'Iyer', 'Jovanovic', 'Keller', 'Lehmann', 'Mendes', 'Nguyen', 'Olsen',
  'Park', 'Richter', 'Santos', 'Torres', 'Urban', 'Vargas', 'Wagner', 'Xu', 'Young', 'Zeller',
  'Adeyemi', 'Brandt', 'Castillo', 'Dietrich', 'Eriksson', 'Fuchs', 'Gomez', 'Haas', 'Ilic', 'Kowalski',
  'Lang', 'Meyer', 'Nowak', 'Ortiz', 'Patel', 'Roth', 'Sauer', 'Thomsen', 'Vidal', 'Winter',
];

// ASCII-fold a name for account names (e.g. "Zoë" -> "zoe").
export function asciiFold(s: string): string {
  return s.normalize('NFKD').replace(/[̀-ͯ]/g, '').replace(/[^A-Za-z]/g, '').toLowerCase();
}
