import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix
from sklearn.tree import DecisionTreeClassifier
import matplotlib.pyplot as plt
from sklearn.metrics import plot_confusion_matrix


dataframe = pd.read_csv('../data/Chicago_Crimes_2012_to_2017.csv')
dataframe.fillna(method='ffill', inplace=True)
# location = dataframe['Location Description'].drop_duplicates().values.tolist()
# location = sorted(location)

# type_of_crimes = dataframe['Primary Type'].drop_duplicates().values.tolist()
description = (dataframe['Description'] + ' ' + dataframe['Location Description']).values.tolist()[:1000]
type_of_crimes = dataframe['Primary Type'].values.tolist()[:1000]

for type in range(len(type_of_crimes)):
    if type_of_crimes[type] == 'GAMBLING':
        type_of_crimes[type] = 0
    elif type_of_crimes[type] == 'HUMAN TRAFFICKING':
        type_of_crimes[type] = 1
    elif type_of_crimes[type] == 'NON-CRIMINAL':
        type_of_crimes[type] = 2
    elif type_of_crimes[type] == 'PUBLIC INDECENCY':
        type_of_crimes[type] = 3
    elif type_of_crimes[type] == 'NARCOTICS':
        type_of_crimes[type] = 4
    elif type_of_crimes[type] == 'NON-CRIMINAL (SUBJECT SPECIFIED)':
        type_of_crimes[type] = 5
    elif type_of_crimes[type] == 'MOTOR VEHICLE THEFT':
        type_of_crimes[type] = 6
    elif type_of_crimes[type] == 'DECEPTIVE PRACTICE':
        type_of_crimes[type] = 7
    elif type_of_crimes[type] == 'OTHER OFFENSE':
        type_of_crimes[type] = 8
    elif type_of_crimes[type] == 'THEFT':
        type_of_crimes[type] = 9
    elif type_of_crimes[type] == 'HOMICIDE':
        type_of_crimes[type] = 10
    elif type_of_crimes[type] == 'ARSON':
        type_of_crimes[type] = 11
    elif type_of_crimes[type] == 'PUBLIC PEACE VIOLATION':
        type_of_crimes[type] = 12
    elif type_of_crimes[type] == 'INTIMIDATION':
        type_of_crimes[type] = 13
    elif type_of_crimes[type] == 'CONCEALED CARRY LICENSE VIOLATION':
        type_of_crimes[type] = 14
    elif type_of_crimes[type] == 'PROSTITUTION':
        type_of_crimes[type] = 15
    elif type_of_crimes[type] == 'CRIM SEXUAL ASSAULT':
        type_of_crimes[type] = 16
    elif type_of_crimes[type] == 'KIDNAPPING':
        type_of_crimes[type] = 17
    elif type_of_crimes[type] == 'STALKING':
        type_of_crimes[type] = 18
    elif type_of_crimes[type] == 'OTHER NARCOTIC VIOLATION':
        type_of_crimes[type] = 19
    elif type_of_crimes[type] == 'BATTERY':
        type_of_crimes[type] = 20
    elif type_of_crimes[type] == 'ASSAULT':
        type_of_crimes[type] = 21
    elif type_of_crimes[type] == 'BURGLARY':
        type_of_crimes[type] = 22
    elif type_of_crimes[type] == 'CRIMINAL TRESPASS':
        type_of_crimes[type] = 23
    elif type_of_crimes[type] == 'ROBBERY':
        type_of_crimes[type] = 24
    elif type_of_crimes[type] == 'INTERFERENCE WITH PUBLIC OFFICER':
        type_of_crimes[type] = 25
    elif type_of_crimes[type] == 'CRIMINAL DAMAGE':
        type_of_crimes[type] = 26
    elif type_of_crimes[type] == 'OFFENSE INVOLVING CHILDREN':
        type_of_crimes[type] = 27
    elif type_of_crimes[type] == 'SEX OFFENSE':
        type_of_crimes[type] = 28
    elif type_of_crimes[type] == 'OBSCENITY':
        type_of_crimes[type] = 29
    elif type_of_crimes[type] == 'NON - CRIMINAL':
        type_of_crimes[type] = 30
    elif type_of_crimes[type] == 'WEAPONS VIOLATION':
        type_of_crimes[type] = 31
    elif type_of_crimes[type] == 'LIQUOR LAW VIOLATION':
        type_of_crimes[type] = 32
    else:
        type_of_crimes[type] = 33

text_clf = Pipeline([
    ('tfidf', TfidfVectorizer()),
    ('clf', DecisionTreeClassifier(random_state=0))
])

train = description[:700]
test = description[700:]
train_type = type_of_crimes[:700]
test_type = type_of_crimes[700:]

text_clf.fit(train, train_type)
titles_options = [("Confusion matrix, without normalization", None),
                  ("Normalized confusion matrix", 'true')]
for title, normalize in titles_options:
    disp = plot_confusion_matrix(text_clf, test, test_type,
                                 cmap=plt.cm.Blues,
                                 normalize=normalize)
    disp.ax_.set_title(title)

    print(title)
    print(disp.confusion_matrix)

plt.show()

preds = text_clf.predict(test)
# filename = 'finalized_model.sav'
# pickle.dump(text_clf, open(filename, 'wb'))
print('DecisionTreeClassifier')
print('accuracy_score:')
print(accuracy_score(test_type, preds))
# print('confusion_matrix:')
# print(confusion_matrix(test_type, preds))